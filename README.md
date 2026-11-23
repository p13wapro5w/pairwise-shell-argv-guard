# pairwise-shell-argv-guard

## 领域

安全

## 主题

命令注入防护

## 说明

argv 传参、模式白名单与最小权限。

初始状态下 `security/shell_argv_guard.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
