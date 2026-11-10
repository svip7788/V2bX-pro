#!/bin/bash
# AnyTLS 回落站点：本机 Nginx 只监听 127.0.0.1，任何 Host 都返回一个普通静态网站。
# 用法：bash fallback_site.sh [端口，默认 8080]
# 卸载：bash fallback_site.sh uninstall   （只删站点配置，不卸载 Nginx）

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

site_root=/var/www/v2bx-fallback
conf_file_name=v2bx-fallback.conf

[[ $EUID -ne 0 ]] && echo -e "${red}请使用 root 运行${plain}" && exit 1

if [[ -f /etc/alpine-release ]]; then
    pm=apk
elif command -v apt-get >/dev/null 2>&1; then
    pm=apt
elif command -v dnf >/dev/null 2>&1; then
    pm=dnf
elif command -v yum >/dev/null 2>&1; then
    pm=yum
else
    echo -e "${red}不支持的系统，请手动安装 Nginx${plain}" && exit 1
fi

# Alpine 的 Nginx 用 http.d，其他发行版用 conf.d
conf_dir=/etc/nginx/conf.d
[[ $pm == apk ]] && conf_dir=/etc/nginx/http.d

service_ctl() {
    if [[ $pm == apk ]]; then
        rc-update add nginx default >/dev/null 2>&1
        rc-service nginx "$1"
    else
        systemctl enable nginx >/dev/null 2>&1
        systemctl "$1" nginx
    fi
}

nginx_running() {
    if [[ $pm == apk ]]; then
        rc-service nginx status >/dev/null 2>&1
    else
        systemctl is-active --quiet nginx
    fi
}

if [[ $1 == uninstall ]]; then
    rm -f "$conf_dir/$conf_file_name"
    rm -rf "$site_root"
    if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1 && nginx_running; then
        service_ctl reload
    fi
    echo -e "${green}已删除回落站点（Nginx 本身保留）${plain}"
    exit 0
fi

port=${1:-8080}
if [[ ! $port =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    echo -e "${red}端口无效：$port${plain}" && exit 1
fi

if ! command -v nginx >/dev/null 2>&1; then
    echo -e "${yellow}安装 Nginx...${plain}"
    case $pm in
        apk) apk add --no-cache nginx curl ;;
        apt) apt-get update -y && apt-get install -y nginx curl ;;
        dnf) dnf install -y nginx curl ;;
        yum) yum install -y epel-release >/dev/null 2>&1; yum install -y nginx curl ;;
    esac
    command -v nginx >/dev/null 2>&1 || { echo -e "${red}Nginx 安装失败${plain}"; exit 1; }
fi
command -v curl >/dev/null 2>&1 || case $pm in
    apk) apk add --no-cache curl ;;
    apt) apt-get install -y curl ;;
    *) $pm install -y curl ;;
esac

# 端口被别的程序占着就退出；被 Nginx 自己占着（重复运行）没关系
if command -v ss >/dev/null 2>&1; then
    holder=$(ss -ltnp 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {print $NF}' | head -1)
    if [[ -n $holder && $holder != *nginx* ]]; then
        echo -e "${red}端口 $port 已被占用：$holder，请换一个端口：bash $0 <端口>${plain}" && exit 1
    fi
fi

# 每台机器随机一个站点名，避免所有节点回落页完全一样
names=("Northwind Studio" "Bluefield Notes" "Maple Lane Journal" "Quiet Harbor" "Copper Trail Blog" "Lumen Works" "Cedar Point Lab" "Silver Birch Diary")
site_name=${names[$((RANDOM % ${#names[@]}))]}
year=$(date +%Y)

mkdir -p "$site_root" "$conf_dir"
cat >"$site_root/index.html" <<EOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${site_name}</title>
<style>
body{margin:0;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;color:#333;background:#fafafa;line-height:1.7}
header{background:#fff;border-bottom:1px solid #eee;padding:24px 0}
.wrap{max-width:760px;margin:0 auto;padding:0 20px}
h1{margin:0;font-size:26px}
nav a{color:#666;margin-right:16px;text-decoration:none;font-size:14px}
article{background:#fff;margin:24px 0;padding:24px;border-radius:6px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
article h2{margin-top:0;font-size:20px}
.meta{color:#999;font-size:13px}
footer{color:#aaa;font-size:13px;text-align:center;padding:32px 0}
</style>
</head>
<body>
<header><div class="wrap"><h1>${site_name}</h1><nav><a href="/">Home</a><a href="/">Archive</a><a href="/">About</a></nav></div></header>
<main class="wrap">
<article><h2>Notes on keeping a small garden</h2><p class="meta">Posted in Life</p>
<p>A few raised beds, some tomatoes and a lot of patience. This season taught me that watering early in the morning makes a bigger difference than any fertilizer I tried.</p></article>
<article><h2>Weekend trip to the coast</h2><p class="meta">Posted in Travel</p>
<p>We left before sunrise and reached the harbor just as the fishing boats were coming back. The small cafe near the pier still serves the best coffee in town.</p></article>
<article><h2>Reading list</h2><p class="meta">Posted in Books</p>
<p>Slowly working through a stack of old paperbacks. Short reviews will follow once I finish a few more of them.</p></article>
</main>
<footer>&copy; ${year} ${site_name}</footer>
</body>
</html>
EOF

cat >"$conf_dir/$conf_file_name" <<EOF
server {
    listen 127.0.0.1:${port} default_server;
    server_name _;
    root ${site_root};
    index index.html;
    server_tokens off;
    access_log off;
    location / {
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

if ! nginx -t >/dev/null 2>&1; then
    nginx -t
    echo -e "${red}Nginx 配置检查失败，已保留 $conf_dir/$conf_file_name 供排查${plain}" && exit 1
fi
if nginx_running; then
    service_ctl reload
else
    service_ctl start
fi

sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: probe.example' "http://127.0.0.1:${port}/")
if [[ $code != 200 ]]; then
    echo -e "${red}回落站点没有正常响应（HTTP $code），请检查 Nginx 日志${plain}" && exit 1
fi

echo -e "${green}回落站点已就绪：http://127.0.0.1:${port}（站点名：${site_name}）${plain}"
echo -e "在面板 AnyTLS 节点「回落」中填写：回落地址 ${yellow}127.0.0.1${plain}，回落端口 ${yellow}${port}${plain}"
