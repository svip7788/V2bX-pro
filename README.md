# V2bX 自用魔改版

基于 [InazumaV/V2bX](https://github.com/InazumaV/V2bX) 的自用魔改版，仅搭配自用的 Xboard 面板（[Xboard-pro](https://github.com/svip7788/Xboard-pro)）使用，不保证与上游或其他面板兼容。

内核只保留 Xray，支持 VMess/VLess、Trojan、Shadowsocks、Hysteria2、TUIC、AnyTLS 协议。

## 魔改内容

* 只保留 Xray 内核（已移除 sing-box），旧配置里的 `sing` 内核自动改用 xray
* 机器模式：面板一键 SSH 安装 / 升级，单机多节点、多面板接入
* WebSocket 实时推送，面板改配置后热重载，不重建入站
* 限制在线 IP / 设备数，设备按网段归并计数，超限设备按面板裁决踢出
* 限制用户连接数：节点默认值 + 面板按用户 `conn_limit` 覆盖，后台可配置并实时生效
* 节点端口级、用户级限速，动态限速（按时间段、速率阈值触发）
* 面板驱动证书配置，QUIC 类协议无证书时自动自签
* BT 封禁、SSH 防护、IP 监控、实时日志、路由转发组
* AnyTLS 服务端按 anytls-go 协议版本 2 对齐，兼容 v1 客户端；支持回落（面板节点配置回落地址），认证失败的连接转发到伪装站点
* 高并发优化，万级用户无锁竞争

## 说明

* Hysteria v1 不再支持（Xray 只实现了 Hysteria2），面板中 V1 节点会被跳过，请改用 V2
* 安装脚本的 `--core` 参数已废弃，传入会被忽略

## 安装

### 一键安装

```bash
wget -N https://raw.githubusercontent.com/svip7788/V2bX-pro/dev_new/install/install.sh && bash install.sh
```

### AnyTLS 回落站点

在节点上一键搭建只监听本机的 Nginx 伪装站点（默认 `127.0.0.1:8080`，可传端口参数；`uninstall` 卸载）：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/svip7788/V2bX-pro/dev_new/install/fallback_site.sh)
```

然后在面板 AnyTLS 节点的「回落」里填写 `127.0.0.1` 和对应端口。

### 手动安装

从 [Releases](https://github.com/svip7788/V2bX-pro/releases) 下载对应平台的 zip 包。

## 构建

```bash
GOEXPERIMENT=jsonv2 go build -v -o V2bX -tags "xray" -trimpath -ldflags "-X 'github.com/InazumaV/V2bX/cmd.version=dev' -s -w -buildid="
```

## 免责声明

* 本项目为个人自用魔改，仅供学习交流使用，使用本项目造成的任何后果由使用者自行承担。

## Thanks

* [InazumaV/V2bX](https://github.com/InazumaV/V2bX)
* [Project X](https://github.com/XTLS/)
* [XrayR](https://github.com/XrayR/XrayR)
* [anytls](https://github.com/anytls/anytls-go)
* [Xboard](https://github.com/cedar2025/Xboard)
