# V2bX 项目主流程

## 项目定位

`V2bX` 本质上是一个运行在节点服务器上的代理守护进程。

它主要做三件大事：

1. 对接面板，拉取节点配置、用户列表、在线设备信息。
2. 启动并管理 `Xray` 内核，承接真实用户连接。
3. 对连接做限速、设备限制、流量统计，再把结果上报回面板。

## 项目主要职责

1. 启动代理内核，提供 VMess、VLESS、Trojan、Shadowsocks、Hysteria、Tuic、AnyTLS 等协议能力。
2. 从面板同步节点配置、用户列表、在线设备状态。
3. 按节点和用户把配置下发到 core。
4. 在连接路径中执行用户限速、节点限速、设备数限制、动态限速、审计规则。
5. 统计每个用户的上下行流量。
6. 周期性把流量和在线设备上报给面板。
7. 支持 WebSocket 实时推送和 HTTP 轮询两种同步模式。
8. 支持配置文件热重载和多节点多进程运行。

## 启动主流程

### 1. 程序入口

入口非常简单：

- `main.go`
- 调用 `cmd.Run()`

### 2. 进入 server 启动逻辑

`cmd/server.go` 的 `serverHandle()` 会做这些事：

1. 读取配置文件。
2. 应用运行时参数，比如 `--pprof-listen`。
3. 初始化日志输出。
4. 判断当前是主进程还是子进程。

## 运行模型

### 主进程模式

主进程主要负责：

1. 解析 `NodeConfig`。
2. 把节点拆成多个 `nodeGroup`。
3. 为每个分组启动一个子进程。
4. 监听配置变更并整体替换 worker。

对应文件：

- `cmd/server_runtime.go`
- 关键函数：`runMasterServer()`、`collectNodeGroups()`、`nodeProcessManager.StartAll()`

### 子进程模式

子进程只负责自己那一组节点：

1. 过滤出当前 group 对应的节点。
2. 准备当前 group 的 core 配置。
3. 初始化 core。
4. 启动 node controllers。

对应函数：

- `runChildGroupServer()`
- `runManagedNodeServer()`

### 为什么这样设计

这样做的目的主要是：

1. 多节点互相隔离。
2. 降低单进程里多个节点互相影响的风险。

## Worker 内部流程

每个 worker 启动后，主线基本是：

1. `limiter.Init()`
2. `vCore.NewCore()`
3. `vc.Start()`
4. `node.New()`
5. `nodes.Start()`

也就是：

`读取节点配置 -> 初始化 core -> 启动 core -> 启动节点控制器`

## 节点控制器流程

每个节点会对应一个 `Controller`，主要在 `node/controller.go`。

### Controller 启动时会做什么

`Controller.Start()` 大致顺序如下：

1. `GetNodeInfo()` 拉节点信息。
2. `GetUserList()` 拉用户列表。
3. `GetUserAlive()` 拉在线设备统计。
4. 创建 limiter。
5. 更新规则。
6. 如果需要 TLS，就处理证书。
7. `server.AddNode()` 把节点加到 core。
8. `server.AddUsers()` 把用户加到 core。
9. 启动定时任务。
10. 尝试连接 WebSocket。

## 面板同步流程

项目现在有两条同步链路：

### 1. HTTP 轮询

轮询主要做两件事：

1. 拉节点信息和用户列表。
2. 上报用户流量和在线设备。

相关文件：

- `node/task.go`
- `node/user.go`
- `api/panel/user.go`

### 2. WebSocket 实时推送

如果面板支持 WS，节点会开启实时推送。

收到推送后会处理这些事件：

1. `sync.config`
2. `sync.users`
3. `sync.user.delta`
4. `sync.devices`

对应逻辑在：

- `node/controller.go`
- 关键函数：`tryStartWebSocket()`、`handleWSEvents()`、`processWSEvent()`

## 用户连接处理流程

用户真实连进来后，主流程可以理解成：

`用户连接 -> core 收到连接 -> 查询 limiter -> 判断是否拒绝 -> 套用限速 -> 计流量 -> 周期上报`

### limiter 主要负责什么

`limiter/limiter.go` 里主要负责：

1. 节点总限速。
2. 用户单独限速。
3. 动态限速。
4. 设备数限制。
5. 在线设备状态维护。
6. 审计规则。

最核心的方法是：

- `CheckLimit()`

它会判断：

1. 用户是否存在。
2. 用户是否超出设备数。
3. 当前连接是否应该拒绝。
4. 当前连接该用哪个限速桶。

## 流量统计与上报流程

这部分主逻辑在 `node/user.go`。

### 周期任务会做什么

`reportUserTrafficTask()` 每轮会做：

1. 从 core 读取当前用户流量切片。
2. 从 limiter 读取在线设备。
3. 先走 V2 上报接口 `Report()`。
4. 如果失败，再回退到 V1 上报。
5. 上报成功后，执行 `CommitUserTraffic()`。

### 这条链路的意义

这样可以避免：

1. 面板接口失败时本地流量被提前清空。
2. 在线设备和流量上报不同步。

## 节点与用户变更流程

定时任务 `nodeInfoMonitor()` 会持续检查面板变化。

### 如果节点配置变了

会走整节点重载流程：

1. 删除旧节点。
2. 更新 limiter。
3. 重新加节点。
4. 重新加用户。
5. 更新定时任务周期。

### 如果只是用户变了

会走增量同步流程：

1. 比较新旧用户列表。
2. 找出新增用户和删除用户。
3. 更新 core 用户。
4. 更新 limiter 用户状态。

## 热重载流程

`conf/watch.go` 会监听：

1. 主配置文件。
2. `dns.json`
3. `route.json`
4. `custom_inbound.json`
5. `custom_outbound.json`

触发后会：

1. 重新加载配置。
2. 调用 reload 回调。
3. 单 worker 模式下重启 core 和 nodes。
4. 多 worker 模式下由主进程替换整批 workers。

## 构建与发布流程

GitHub Actions 的流程很清楚：

### push / pull_request

会触发多平台构建，主要产出构建结果和 artifacts。

### release

会触发正式发布流程：

1. 多平台构建。
2. 打 zip 包。
3. 附带示例配置和数据文件。
4. 上传到 GitHub Releases。

相关文件：

- `.github/workflows/release.yml`

## 核心文件一览

| 文件 | 作用 |
| --- | --- |
| `main.go` | 程序入口 |
| `cmd/server.go` | `server` 启动命令入口 |
| `cmd/server_runtime.go` | 主进程、子进程、worker 管理、热重载 |
| `node/node.go` | 启动所有节点控制器 |
| `node/controller.go` | 单节点生命周期、WS 事件、用户同步 |
| `node/task.go` | 定时任务：轮询、证书续期、动态限速 |
| `node/user.go` | 流量与在线设备上报 |
| `api/panel/user.go` | 面板接口：拉用户、拉在线、上报流量 |
| `limiter/limiter.go` | 限速、设备数限制、在线设备状态 |
| `conf/watch.go` | 配置监听与热重载 |
| `core/interface.go` | core 统一抽象接口 |

## 一句话总览

`V2bX` 可以理解成：

`面板同步器 + 节点运行管理器 + 连接限速器 + 流量统计上报器`

它不是单纯的代理内核，而是套在 `Xray` 外面的一层“节点控制系统”。
