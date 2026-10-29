#!/bin/sh
# 按本机内存 / CPU / 内核 / 虚拟化类型自动计算网络参数并开启 BBR，可重复执行
if [ "$(id -u)" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi
CONF=/etc/sysctl.d/99-bbr-optimize.conf

# ---------- 探测 ----------
MEM_KB=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)
[ -n "$MEM_KB" ] || MEM_KB=1048576
MEM_MB=$((MEM_KB / 1024))
CPUS=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null)
[ -n "$CPUS" ] && [ "$CPUS" -gt 0 ] || CPUS=1
KVER=$(uname -r)
KMAJ=$(echo "$KVER" | cut -d. -f1)
KMIN=$(echo "$KVER" | cut -d. -f2 | sed 's/[^0-9].*//')
KNUM=$((KMAJ * 100 + ${KMIN:-0}))

VIRT=""
if command -v systemd-detect-virt >/dev/null 2>&1; then
    VIRT=$(systemd-detect-virt 2>/dev/null)
fi
if [ -z "$VIRT" ] || [ "$VIRT" = "none" ]; then
    if [ -e /proc/user_beancounters ]; then VIRT=openvz
    elif grep -qa 'container=lxc' /proc/1/environ 2>/dev/null; then VIRT=lxc
    elif [ -e /.dockerenv ]; then VIRT=docker
    else VIRT=${VIRT:-none}
    fi
fi
CONTAINER=0
case "$VIRT" in openvz|lxc|lxc-libvirt|docker|podman|systemd-nspawn|wsl) CONTAINER=1 ;; esac

# ---------- 按内存分档 ----------
# buf: 单连接缓冲上限（够 1Gbps×250ms 的 BDP 即可，再大只会放大内存压力）
if   [ "$MEM_MB" -le 640 ];   then TIER="≤640M";  BUF=8388608;  DEF=87380;  CONN=8192;  TW=50000;   CT=65536
elif [ "$MEM_MB" -le 1536 ];  then TIER="≤1.5G";  BUF=16777216; DEF=131072; CONN=16384; TW=100000;  CT=131072
elif [ "$MEM_MB" -le 4096 ];  then TIER="≤4G";    BUF=33554432; DEF=131072; CONN=32768; TW=200000;  CT=262144
elif [ "$MEM_MB" -le 16384 ]; then TIER="≤16G";   BUF=67108864; DEF=262144; CONN=65535; TW=500000;  CT=524288
else                               TIER=">16G";   BUF=67108864; DEF=262144; CONN=65535; TW=1000000; CT=1048576
fi

# tcp_mem / udp_mem 单位是页：小内存机器给 V2bX 本身留出余量
PAGES=$((MEM_KB / 4))
if [ "$MEM_MB" -le 1536 ]; then
    MEM_LOW=$((PAGES / 8)); MEM_PRESS=$((PAGES / 4)); MEM_HIGH=$((PAGES * 3 / 8))
else
    MEM_LOW=$((PAGES / 4)); MEM_PRESS=$((PAGES / 3)); MEM_HIGH=$((PAGES / 2))
fi

# 收包队列按核数放大
BACKLOG=$((CPUS * 8192))
[ "$BACKLOG" -lt 16384 ] && BACKLOG=16384
[ "$BACKLOG" -gt 262144 ] && BACKLOG=262144

# 文件句柄不得低于 V2bX.service 的 LimitNOFILE=999999
FILE_MAX=$((MEM_MB * 1024))
[ "$FILE_MAX" -lt 1048576 ] && FILE_MAX=1048576
[ "$FILE_MAX" -gt 16777216 ] && FILE_MAX=16777216

# ---------- 拥塞控制 ----------
CC=cubic
QDISC=fq
BBR_NOTE=""
if [ "$KNUM" -lt 409 ]; then
    BBR_NOTE="内核 $KVER 低于 4.9，不支持 BBR"
else
    $SUDO modprobe tcp_bbr 2>/dev/null || true
    if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
        CC=bbr
        if [ -d /etc/modules-load.d ] && ! grep -qs "^tcp_bbr" /etc/modules-load.d/bbr.conf; then
            echo "tcp_bbr" | $SUDO tee /etc/modules-load.d/bbr.conf >/dev/null 2>&1 || true
        fi
    elif [ "$CONTAINER" -eq 1 ]; then
        BBR_NOTE="$VIRT 容器无法加载内核模块，BBR 需在宿主机开启"
    else
        BBR_NOTE="内核未编译 BBR 模块"
    fi
fi

# ---------- 生成配置 ----------
$SUDO tee "$CONF" >/dev/null <<EOF
# 由 V2bX bbr 生成：${MEM_MB}MB 内存 / ${CPUS} 核 / 内核 ${KVER} / ${VIRT}
net.core.default_qdisc = ${QDISC}
net.ipv4.tcp_congestion_control = ${CC}
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_notsent_lowat = 131072

net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_tw_buckets = ${TW}
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = ${CONN}
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.core.somaxconn = ${CONN}
net.core.netdev_max_backlog = ${BACKLOG}

net.core.rmem_max = ${BUF}
net.core.wmem_max = ${BUF}
net.core.rmem_default = ${DEF}
net.core.wmem_default = ${DEF}
net.ipv4.tcp_rmem = 4096 ${DEF} ${BUF}
net.ipv4.tcp_wmem = 4096 65536 ${BUF}
net.ipv4.tcp_mem = ${MEM_LOW} ${MEM_PRESS} ${MEM_HIGH}
net.ipv4.udp_mem = ${MEM_LOW} ${MEM_PRESS} ${MEM_HIGH}
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
fs.file-max = ${FILE_MAX}
fs.nr_open = ${FILE_MAX}
EOF

CT_LINE=""
if [ -e /proc/sys/net/netfilter/nf_conntrack_max ]; then
    CT_LINE="已调整 ${CT}"
    $SUDO tee -a "$CONF" >/dev/null <<EOF
net.netfilter.nf_conntrack_max = ${CT}
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30
net.netfilter.nf_conntrack_udp_timeout = 30
net.netfilter.nf_conntrack_udp_timeout_stream = 120
EOF
    [ -w /sys/module/nf_conntrack/parameters/hashsize ] && echo $((CT / 4)) | $SUDO tee /sys/module/nf_conntrack/parameters/hashsize >/dev/null 2>&1
fi

# 旧版脚本写的固定参数会与之冲突
$SUDO sed -i '/tcp_adv_win_scale/d' /etc/sysctl.conf 2>/dev/null || true

# ---------- 逐项应用，记录容器里改不了的项 ----------
FAILED=""
OK_COUNT=0
TMP=$(mktemp 2>/dev/null || echo /tmp/v2bx-bbr.$$)
grep -E '^[a-z]' "$CONF" > "$TMP"
while IFS= read -r line; do
    key=$(echo "$line" | cut -d= -f1 | tr -d ' ')
    val=$(echo "$line" | cut -d= -f2- | sed 's/^ *//')
    if $SUDO sysctl -w "$key=$val" >/dev/null 2>&1; then
        OK_COUNT=$((OK_COUNT + 1))
    else
        FAILED="$FAILED $key"
    fi
done < "$TMP"
rm -f "$TMP"

if ! grep -qs "nofile 1048576" /etc/security/limits.conf; then
    $SUDO sed -i '/^[^#].*\(nofile\|nproc\)/d' /etc/security/limits.conf 2>/dev/null || true
    printf '* soft nofile 1048576\n* hard nofile 1048576\n* soft nproc 1048576\n* hard nproc 1048576\nroot soft nofile 1048576\nroot hard nofile 1048576\nroot soft nproc 1048576\nroot hard nproc 1048576\n' | $SUDO tee -a /etc/security/limits.conf >/dev/null 2>&1 || true
fi

# ---------- 结果 ----------
mb() { echo "$(( $1 / 1048576 ))MB"; }
echo ">>> 机器: ${MEM_MB}MB 内存（档位 ${TIER}）/ ${CPUS} 核 / 内核 ${KVER} / 虚拟化 ${VIRT}"
echo ">>> 拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)  队列: $(sysctl -n net.core.default_qdisc 2>/dev/null)  TFO: $(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null)"
[ -n "$BBR_NOTE" ] && echo ">>> BBR 未开启: ${BBR_NOTE}"
echo ">>> 单连接缓冲上限 $(mb "$BUF")，TCP/UDP 总内存上限 $((MEM_HIGH * 4 / 1024))MB，连接队列 ${CONN}，收包队列 ${BACKLOG}"
echo ">>> 连接跟踪: ${CT_LINE:-未加载 nf_conntrack，跳过}"
echo ">>> 已应用 ${OK_COUNT} 项$([ -n "$FAILED" ] && echo "，以下 $(echo $FAILED | wc -w) 项当前环境不允许修改（容器/内核限制，可忽略）:")"
[ -n "$FAILED" ] && echo "   $FAILED"
echo ">>> 优化完成，无需重启"
