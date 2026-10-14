"""轻量静态检查：语法、未使用导入、模块可导入性（不依赖第三方工具）。"""
import ast
import os
import sys

root = os.path.dirname(os.path.abspath(__file__))
targets = []
for dirpath, dirnames, filenames in os.walk(os.path.join(root, "wsa")):
    dirnames[:] = [d for d in dirnames if d != "__pycache__"]
    for f in filenames:
        if f.endswith(".py"):
            targets.append(os.path.join(dirpath, f))
for extra in ("wsp.py", "selftest.py"):
    targets.append(os.path.join(root, extra))

problems = []
for path in sorted(targets):
    src = open(path, encoding="utf-8").read()
    try:
        tree = ast.parse(src, path)
    except SyntaxError as exc:
        problems.append(f"{os.path.relpath(path, root)}: 语法错误 {exc}")
        continue
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[(a.asname or a.name.split(".")[0])] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                if a.name != "*":
                    imported[(a.asname or a.name)] = node.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    used |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            used.add(node.value.id)
    for name, lineno in imported.items():
        if name == "annotations":
            continue
        if name not in used:
            problems.append(f"{os.path.relpath(path, root)}:{lineno}: 可能未使用的导入 {name}")

print(f"检查文件数：{len(targets)}")
for p in problems:
    print("  -", p)
if not problems:
    print("未发现语法问题或未使用的导入")

sys.path.insert(0, root)
mods = []
for dirpath, dirnames, filenames in os.walk(os.path.join(root, "wsa")):
    dirnames[:] = [d for d in dirnames if d != "__pycache__"]
    for f in filenames:
        if f.endswith(".py") and f != "__init__.py":
            mods.append(os.path.relpath(os.path.join(dirpath, f), root)[:-3].replace(os.sep, "."))
fails = []
for m in sorted(mods):
    try:
        __import__(m)
    except Exception as exc:
        fails.append(f"{m}: {type(exc).__name__} {exc}")
print(f"\n模块导入检查：{len(mods)} 个模块，失败 {len(fails)} 个")
for f in fails:
    print("  -", f)
sys.exit(1 if (problems or fails) else 0)
