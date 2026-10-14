# WebShell 排查与处置清单（可直接照着做）

> 配套工具：`webshell-watch`（本仓库）。告警里会给出文件路径、来源 IP、载荷明文片段与建议，
> 下面是把它落到操作层面的完整流程。
>
> 原则：**先取证，再断链，最后清理**。不要一上来就 `rm`。

---

## 0. 收到告警后的 5 分钟动作

| 步骤 | 命令 | 目的 |
|---|---|---|
| 1. 看告警详情 | `wsp report` / `tail -50 /var/log/webshell-watch/alerts-*.log` | 确认工具类型、来源 IP、URL、证据 |
| 2. 定位真实文件 | `sudo wsp filescan`（或按告警 URL 到 Web 目录找同名文件） | 拿到绝对路径 |
| 3. 保全证据 | 见下方「P1 取证」 | 后续溯源与报案都要用 |
| 4. 断链 | 见下方「P2 断链」 | 阻止继续被控 |
| 5. 查持久化 | 见下方「P3 排查」 | 攻击者不会只放一个马 |

---

## P1 取证（先做，不可跳过）

```bash
# 1) 建立事件目录
sudo mkdir -p /root/incident/$(date +%Y%m%d-%H%M) && cd /root/incident/$(date +%Y%m%d-%H%M)

# 2) 复制马文件（不要移动、不要删除）
sudo cp -a /var/www/html/upload/shell.php ./shell.php.evidence
sudo sha256sum ./shell.php.evidence | tee hash.txt
sudo stat /var/www/html/upload/shell.php | tee stat.txt
sudo ls -l --time-style=full-iso /var/www/html/upload/ | tee dir-listing.txt

# 3) 抓取相关访问日志（按马文件路径筛）
sudo grep -a "shell.php" /var/log/nginx/access.log* > access-shell.log
# 最早一次访问时间就是入侵时间窗起点
head -3 access-shell.log

# 4) 保留当前网络连接与进程快照
sudo ss -antp > netstat.txt
sudo ps auxf > ps.txt

# 5) 打包留档
sudo tar czf /root/incident-$(date +%Y%m%d-%H%M).tar.gz -C /root/incident .
```

如果文件内容需要人工确认，本工具已把命中的特征片段放在告警 `evidence` 字段里，
也可以直接：

```bash
grep -nE "eval|assert|base64_decode|system|shell_exec|openssl_decrypt" 马文件
```

---

## P2 断链（取证完成后）

```bash
# 1) 让马暂时失效（比删除好：保留现场，攻击者仍会来打，可继续观察）
sudo chmod 000 /var/www/html/upload/shell.php
sudo chown root:root /var/www/html/upload/shell.php
# 或者改名成不可执行的扩展名
sudo mv /var/www/html/upload/shell.php /var/www/html/upload/shell.php.disabled

# 2) 在 nginx 层阻断该路径（防止其它马继续被调用）
#    在对应 server{} 中加：
#      location = /upload/shell.php { deny all; }
sudo nginx -t && sudo systemctl reload nginx

# 3) 封禁来源 IP（确认不是自己的扫描器/监控再封）
sudo nft add rule inet filter input ip saddr 198.51.100.7 drop
# 或 ufw：sudo ufw deny from 198.51.100.7

# 4) 如果 SSH 也被爆破成功过，立刻处理
sudo passwd -l 可疑账号
sudo sed -i '/可疑公钥/d' /root/.ssh/authorized_keys   # 先备份该文件！
```

> 注意：**改文件权限/改名后要重新跑一次基线**，否则文件巡检会持续告警：
> `sudo wsp filescan --update-baseline`

---

## P3 排查持久化与横向移动

按顺序逐项确认，任何一项有非本人操作都要继续挖：

```bash
# 1) SSH 公钥（webshell 落地后最常见的持久化）
ls -l --time-style=full-iso /root/.ssh/ /home/*/.ssh/
cat /root/.ssh/authorized_keys

# 2) 账号
awk -F: '$3>=1000 {print $1, $3, $6, $7}' /etc/passwd
grep -E ":[0-9]{10,}:" /etc/shadow | cut -d: -f1     # 最近改过密码的
sudo lastlog | grep -v "Never"

# 3) 计划任务
crontab -l; sudo ls -l /etc/cron.* /var/spool/cron/crontabs/
systemctl list-timers --all

# 4) 开机自启 / 可疑服务
systemctl list-unit-files --state=enabled
sudo ls -l /etc/init.d/ /etc/systemd/system/*.service

# 5) 临时目录与可疑可执行文件（webshell 常在这里放工具）
sudo ls -la /tmp /var/tmp /dev/shm
sudo find /tmp /var/tmp /dev/shm -type f -newermt '-7 days' -ls

# 6) 反弹 shell 与挖矿特征
sudo ss -antp | grep ESTAB
ps aux --sort=-%cpu | head -15
sudo grep -rE "curl|wget|base64 -d|/dev/tcp" /tmp /var/tmp 2>/dev/null

# 7) Web 目录内的新增/异常文件（工具已做，手工再确认一次）
sudo find /var/www -type f -newermt '-7 days' -ls
sudo find /var/www -type f \( -name "*.py" -o -name "*.pl" -o -name "*.sh" -o -name "*.cgi" \) -ls

# 8) 内核级后门/rootkit（有疑点再用）
sudo apt-get install -y chkrootkit rkhunter && sudo rkhunter --check --sk
```

---

## P4 清理与恢复

```bash
# 1) 删除确认恶意的文件（证据已留档后）
sudo rm -f /var/www/html/upload/shell.php

# 2) 轮换全部凭据（马存在期间，攻击者可能已经读到配置文件）
#    - 数据库密码、云 AK/SK、第三方 API Key
#    - 应用配置里的密钥（.env / config.php / application.yml）
#    - SSH 密钥对（重新生成，旧公钥从所有机器移除）

# 3) 用干净副本恢复被篡改的业务文件
#    从 git/发布包重新部署，不要手工打补丁

# 4) 重新建立文件基线
sudo wsp filescan --update-baseline
```

---

## P5 加固（防止再来一次）

```bash
# 1) 上传目录禁止执行脚本（挡掉绝大多数上传型 webshell）
#    nginx:
#      location ^~ /uploads/ { location ~ \.(php|jsp|asp|aspx|sh|py)$ { return 403; } }

# 2) 代码属主改 root，去掉 Web 进程的写权限
sudo chown -R root:root /var/www/html
sudo find /var/www/html -type d -exec chmod 755 {} \;
sudo find /var/www/html -type f -exec chmod 644 {} \;

# 3) PHP 加固（php.ini 或 pool 配置）
#    open_basedir = /var/www/html:/tmp
#    disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
#    allow_url_include = Off
#    expose_php = Off

# 4) SSH 加固
#    PasswordAuthentication no        # 改用密钥
#    PermitRootLogin prohibit-password
sudo apt-get install -y fail2ban       # 自动封禁爆破来源

# 5) 审计关键目录变更（与本工具文件巡检双保险）
sudo apt-get install -y auditd
echo "-w /var/www/html -p wa -k webroot_change" | sudo tee -a /etc/audit/rules.d/webroot.rules
sudo systemctl restart auditd

# 6) 让本工具持续运行
sudo systemctl enable --now webshell-watch
sudo systemctl status webshell-watch
```

---

## P6 长期运行建议

* **务必开启请求体日志**，否则加密马测不出来（`/etc/webshell-watch/nginx-request-body.conf`）
* 把告警 JSONL 接入现有 SIEM：`/var/log/webshell-watch/alerts-*.jsonl`（一行一条）
* 高危告警接到 IM：配置 `webhook`（钉钉/企业微信/Slack）
* 每周看一次统计：`wsp report`
* **每次正常发布代码后**：`sudo wsp filescan --update-baseline`
* 定期验证工具本身还在工作：`wsp check`

---

## 附：常见误报与处理

| 告警 | 常见原因 | 处理 |
|---|---|---|
| DEF-001 POST 脚本无 Referer | 移动端 App、第三方回调、接口直连 | 把该路径加自定义规则白名单，或调低该规则分值 |
| DEF-010 扫描器 UA | 自己安排的 AWVS/nuclei 扫描 | 把扫描器出口 IP 加入信任列表（或接受这条告警作为审计记录） |
| DEF-011 命令执行关键字 | 业务本身有 `cmd` 参数名（如支付回调） | 用 `require_regex` 收紧到「参数值含 whoami/id 等」 |
| DEF-030 新增脚本 | 正常发布、上传用户文件 | 核对发布记录后 `wsp filescan --update-baseline` |
| DEF-033 权限异常 | 历史遗留 777 文件 | 执行 P5 第 2 步统一收敛权限 |
| DEF-040 SSH 爆破 | 互联网暴露的 22 端口被扫 | 改端口/仅密钥登录/上 fail2ban，告警保留作为记录 |
| DEF-041 SSH 登录成功 | 你自己的运维 IP | 把跳板机 IP 写进 `authlog.trusted_ips` |
| DEF-042 sudo 提权 | 运维例行操作 | 若你的运维全走 sudo，可把该规则改为 `enabled: false` |
