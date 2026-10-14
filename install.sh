#!/usr/bin/env bash
# ============================================================================
# WebShell 防守监控 —— Ubuntu 24.04 一键安装
#
#   sudo ./install.sh              安装并启用服务
#   sudo ./install.sh --no-start   只安装，不启动
#   sudo ./install.sh --uninstall  卸载（保留日志）
#
# 安装内容：
#   /opt/webshell-watch/          程序本体
#   /etc/webshell-watch/config.json  配置
#   /var/log/webshell-watch/      告警与运行日志
#   /var/lib/webshell-watch/      文件基线、pcap 目录
#   /etc/systemd/system/webshell-watch.service
#   /etc/logrotate.d/webshell-watch
# ============================================================================
set -euo pipefail

APP_DIR="/opt/webshell-watch"
ETC_DIR="/etc/webshell-watch"
LOG_DIR="/var/log/webshell-watch"
STATE_DIR="/var/lib/webshell-watch"
SVC_NAME="webshell-watch"
SERVICE_FILE="/etc/systemd/system/${SVC_NAME}.service"

START_SERVICE=1
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --no-start) START_SERVICE=0 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "[错误] 请用 sudo 运行：sudo $0" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
if [[ $UNINSTALL -eq 1 ]]; then
  echo "==> 卸载 ${SVC_NAME}"
  systemctl stop "${SVC_NAME}" 2>/dev/null || true
  systemctl disable "${SVC_NAME}" 2>/dev/null || true
  rm -f "${SERVICE_FILE}" /etc/logrotate.d/${SVC_NAME}
  systemctl daemon-reload
  rm -rf "${APP_DIR}"
  echo "已移除程序与 systemd 单元。配置(${ETC_DIR})、日志(${LOG_DIR})、状态(${STATE_DIR}) 已保留，如需彻底清理请手动删除。"
  exit 0
fi

# ---------------------------------------------------------------------------
echo "==> 检查运行环境"
if ! command -v python3 >/dev/null 2>&1; then
  echo "[错误] 未找到 python3。请先执行：apt-get install -y python3" >&2
  exit 1
fi
PY_VER="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "    python3 版本：${PY_VER}"
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then
  echo "[错误] 需要 Python 3.9 及以上（Ubuntu 24.04 自带 3.12，满足要求）" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
echo "==> 安装程序到 ${APP_DIR}"
mkdir -p "${APP_DIR}"
cp -r "${SRC_DIR}/wsa" "${APP_DIR}/"
cp "${SRC_DIR}/wsp.py" "${APP_DIR}/"
find "${APP_DIR}" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
chmod 0755 "${APP_DIR}/wsp.py"
# 让命令行可以直接用 wsp（固定使用 Linux 版配置）
cat > /usr/local/bin/wsp <<'EOF'
#!/bin/sh
# WebShell 防守监控（Linux 版）—— 固定使用 /etc/webshell-watch/config.json
WW_CONFIG="${WW_CONFIG:-/etc/webshell-watch/config.json}"
export WW_CONFIG
exec /usr/bin/python3 /opt/webshell-watch/wsp.py "$@"
EOF
chmod 0755 /usr/local/bin/wsp

echo "==> 准备配置与目录"
mkdir -p "${ETC_DIR}" "${LOG_DIR}" "${STATE_DIR}/pcap" "${ETC_DIR}/rules"
if [[ ! -f "${ETC_DIR}/config.json" ]]; then
  # 用 Linux 版默认配置（linux.json）；若不存在则退回通用配置
  if [[ -f "${SRC_DIR}/linux.json" ]]; then
    install -m 0640 "${SRC_DIR}/linux.json" "${ETC_DIR}/config.json"
  else
    install -m 0640 "${SRC_DIR}/config.json" "${ETC_DIR}/config.json"
  fi
  echo "    已生成 ${ETC_DIR}/config.json（Linux 版默认路径）"
else
  echo "    已存在 ${ETC_DIR}/config.json，保留现有配置"
fi
if [[ -d "${SRC_DIR}/rules" ]]; then
  cp -n "${SRC_DIR}/rules/"*.json "${ETC_DIR}/rules/" 2>/dev/null || true
fi

# 明确关闭 Windows 专属模块（同一份配置可能在两个平台间同步）
if command -v python3 >/dev/null 2>&1; then
  WW_ETC_CONFIG="${ETC_DIR}/config.json" python3 - <<'PYEOF' 2>/dev/null || true
import json, os
path = os.environ.get("WW_ETC_CONFIG", "/etc/webshell-watch/config.json")
try:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    for key in ("iislog", "winevent", "windrop", "authlog"):
        data.setdefault(key, {})
    data["iislog"]["enabled"] = False
    data["winevent"]["enabled"] = False
    data["windrop"]["enabled"] = False
    data["authlog"]["enabled"] = True
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    print("    已按 Linux 平台调整模块开关（关闭 IIS/Windows 事件日志/落地目录扫描）")
except Exception as exc:
    print(f"    平台开关调整跳过：{exc}")
PYEOF
fi

# 目录权限：日志与状态目录仅 root 可写，其他用户只读
chmod 0750 "${LOG_DIR}" "${STATE_DIR}"
chown -R root:root "${APP_DIR}" "${ETC_DIR}"
chown -R root:root "${LOG_DIR}" "${STATE_DIR}"

# ---------------------------------------------------------------------------
echo "==> 写入 systemd 单元"
cat > "${SERVICE_FILE}" <<'EOF'
[Unit]
Description=WebShell Defense Monitor (webshell traffic & artifact detection)
Documentation=file:/opt/webshell-watch/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# 需要读 /var/log/nginx、/var/log/auth.log 并做 Web 目录巡检，因此以 root 运行。
# 若你的环境不允许 root，可改为专用用户并为其授予日志读权限，
# 同时把 sniff.enabled 保持为 false（抓包需要 CAP_NET_RAW）。
User=root
WorkingDirectory=/opt/webshell-watch
ExecStart=/usr/bin/python3 /opt/webshell-watch/wsp.py --config /etc/webshell-watch/config.json start
Restart=always
RestartSec=5
# 抓到问题就重启但不要疯狂重启
StartLimitIntervalSec=300
StartLimitBurst=5
# 基本加固：只读系统、仅可写自己的目录
NoNewPrivileges=false
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=/var/log/webshell-watch /var/lib/webshell-watch
StandardOutput=journal
StandardError=journal
SyslogIdentifier=webshell-watch

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/logrotate.d/${SVC_NAME} <<EOF
${LOG_DIR}/*.log ${LOG_DIR}/*.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    create 0640 root root
}
EOF

# ---------------------------------------------------------------------------
echo "==> 生成 nginx 请求体日志配置示例"
cat > "${ETC_DIR}/nginx-request-body.conf" <<'EOF'
# ---------------------------------------------------------------------------
# 让 nginx 记录 POST 请求体 —— 这是本工具检测加密型 webshell 的前提。
#
# 用法（放在 nginx.conf 的 http {} 块里，或 conf.d/ 下的 .conf 文件中）：
#   1. 粘贴下面的 log_format 定义；
#   2. 在你的 server {} / location {} 里使用：
#        access_log /var/log/nginx/access.log webshell_detect;
#   3. 重载：nginx -t && systemctl reload nginx
#
# 注意：
#   * $request_body 只有在请求体已被读取时才非空（proxy_pass / fastcgi_pass
#     之后一定有值；纯静态目录通常为空）。
#   * nginx 记录时会做转义（\xNN），本工具会自动还原。
#   * 请求体会进入日志文件，注意日志目录权限（建议 0640 root:adm），
#     并设置合理的 logrotate。
# ---------------------------------------------------------------------------

log_format webshell_detect '$remote_addr - $remote_user [$time_local] '
                           '"$request" $status $body_bytes_sent '
                           '"$http_referer" "$http_user_agent" '
                           '$request_body';

# 如果不想记录全部请求体（日志会变大），可以只对脚本请求记录：
map $request_uri $log_body {
    default          "";
    ~*\.(php|jsp|jspx|asp|aspx|ashx|phtml)  $request_body;
}
log_format webshell_detect_light '$remote_addr - $remote_user [$time_local] '
                                 '"$request" $status $body_bytes_sent '
                                 '"$http_referer" "$http_user_agent" '
                                 '$log_body';
EOF
echo "    已生成 ${ETC_DIR}/nginx-request-body.conf"

# ---------------------------------------------------------------------------
echo "==> 运行自检"
python3 "${APP_DIR}/wsp.py" --config "${ETC_DIR}/config.json" check || true

if [[ $START_SERVICE -eq 1 ]] && command -v systemctl >/dev/null 2>&1; then
  echo "==> 启用并启动服务"
  systemctl daemon-reload
  systemctl enable "${SVC_NAME}" >/dev/null 2>&1 || true
  systemctl restart "${SVC_NAME}"
  sleep 2
  systemctl --no-pager --lines=15 status "${SVC_NAME}" || true
fi

cat <<EOF

============================================================================
安装完成。
----------------------------------------------------------------------------
常用命令：
    systemctl status webshell-watch        # 查看运行状态
    journalctl -u webshell-watch -f        # 实时看运行日志
    tail -f ${LOG_DIR}/alerts-$(date +%Y%m%d).jsonl   # 实时看告警
    wsp report                             # 查看告警统计
    wsp check                              # 重新自检
    sudo wsp filescan --update-baseline    # 发布代码后更新文件基线

重要提醒：
  1. 默认日志格式没有 POST 请求体，只能检测「明文的蚁剑类」流量。
     请按 ${ETC_DIR}/nginx-request-body.conf 开启 $request_body 记录，
     否则冰蝎/哥斯拉这类加密马检测能力很弱。
  2. 如果服务器同时开了 pcap 抓包目录，把抓包文件放到
     ${STATE_DIR}/pcap 并把配置里 pcap.enabled 设为 true 即会自动分析。
============================================================================
EOF
