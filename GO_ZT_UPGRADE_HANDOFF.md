# ZeroTier / libbox 升级交接

## 当前迁移：sing-box 1.14.3

- 上游固定为 `v1.14.3`（`7054cac5124465ffdb145870d7c01885566711b1`），不跟随 `testing` 或未发布的稳定分支 HEAD。
- go-zt 继续固定 `b80d38ba2346bb2bc51eed61f5babbe0f978965b`，通过现有远程 module replacement 获取，不引用本地工作区。
- ZeroTier 接入新的 `Scope`、`JudgeFlow` 和 DNS packet 接口；UDP forwarder 必须显式启动，UDP/ICMP forwarder 在栈销毁前关闭。保留 Node 同步回调之外发送 ICMP 回复的边界。
- Android 交付保持 API 34、`arm64-v8a`、Java package `libbox`、入口 `libbox.Libbox`、`jni/arm64-v8a/libbox.so`，以及 `with_gvisor,with_quic,with_clash_api,with_zerotier` 标签。
- 构建采用 `release/LDFLAGS` / `cmd/internal/build_shared.LinkerFlags` 的当前 linker 约定；不要沿用旧 GODEBUG 符号或省略 `-checklinkname=0`。
- 最终产物位于独立的 `build/migration-v1.14.3-<源码短 SHA>/`，源码提交、完整构建命令、工具链和校验和以同目录 provenance 为准。根目录的 1.13.14 产物保留。

NexBox 必须按实际生成的 Java API 适配 `PlatformInterface`、command handlers 和返回迭代器的 TUN DNS getter；不能只替换 AAR。旧版真机验收记录不能代替新版运行验收。

需要解析域名的拨号路径在存在多个 DNS transport 时，必须通过 `domain_resolver` 或 `route.default_domain_resolver` 明确选择解析器；少于两个 DNS transport 时仍可使用默认解析器，不应机械增加字段。不要借弃用环境变量绕过 1.14 校验。

### 已知限制

1.14.3 的 sing-tun `ICMPForwarder` 不消费 `FlowVerdict.Destination`。隔离收包探针已确认：路由要求把 ICMP 目标从 FakeIP 改为真实 IP 时，转发端仍收到原目标。它不影响直接访问真实 ZeroTier IP，也不涉及普通 TCP/UDP 转发。本轮按用户决定不修复该依赖问题，迁移完成后再跟进上游；未声称已完成旧版或 Android 的端到端 FakeIP ping 对照。

## 历史：2026-07 go-zt 升级

目标：在 `stable-zerotier` 分支升级到最新 go-zt，并产出可供 NexBox 使用的 `libbox.aar`。

### 处理方向

1. **修复 ICMP 回调重入**  
   `protocol/zerotier/icmp_forwarder.go` 当前在 ZeroTier 同步回调中直接调用 `Node.ProcessVirtualNetworkFrame`。恢复为 `ep.goManaged(...)` 异步发送，并补一个“回调返回前不调用 Node”的回归测试。

2. **固定依赖版本**  
   将 go-zt 固定到已验证提交 `b80d38b` 或其后继；交付时移除 `replace ... => ../go-zt`。同时解决 go-zt 模块路径与实际 GitHub 仓库地址不一致的问题，确保干净环境可复现构建。

3. **重建并交接 libbox**  
   使用 Android API 34、arm64 和现有 `with_gvisor,with_quic,with_clash_api,with_zerotier` 标签重建 AAR。记录 sing-box/go-zt 的确切提交；不要把 `(devel)` 或本地 replace 构建交给 NexBox。

### 最低验收

- ZeroTier 包普通测试与 Race 测试通过。
- `go build` 全量通过。
- AAR 构建成功。
- NexBox 侧完成编译，并验证 ZeroTier join/leave、ICMP、快速启停。

不要修改 go-zt 去支持普通 Node 方法的同步回调重入；异步退出回调边界是这里的正确修复。

## 历史复核记录（2026-07-18）

**判定**：升级与 NexBox 同步已经工作，但当前 ZeroTier endpoint 仍有 9 个 P1、6 个 P2，阻塞发布。除 ICMP 异步修复及其测试外，核心 endpoint 实现与旧 `c117cda1` 树一致；下列问题多数是沿用问题，不是本次 AAR 同步新增。

### 交付基线

- sing-box：`23fab0e890285336b102530f901f990d8e4cd4f1`
- go-zt：`b80d38ba2346bb2bc51eed61f5babbe0f978965b`
- NexBox：`2d98abb2f4ea188f355786d21e6dcd9a709e3d31`
- AAR SHA-256：`eadb27635c34a3f769d7b6db08ebae9962251895e5dbcdff12f58efa511f1f5a`
- AAR：Android API 34、arm64、`libbox.so`
- 构建标签：`with_gvisor,with_quic,with_clash_api,with_zerotier`
- 工具链：Go 1.25.8
- 运行时版本：`1.13.14-23fab0e8`

仓库尚未记录生成该 AAR 的完整构建命令。正式交付前应增加 artifact manifest，将完整源码 SHA、工具链、构建命令、标签、API/ABI 和 checksum 绑定在一起。

### 已验证

- ZeroTier Race 测试、`go vet` 和 tagged 全量构建通过。
- NexBox Flutter Analyze、4 项测试、Android Lint、Debug APK 构建通过。
- Android 真机 ZeroTier 为 `Online` / `Status OK`，获得地址 `10.255.111.61/14` 和 peers。
- `10.254.0.1` ICMP 3/3，0% 丢包。
- 以 200 ms 间隔连续完成 5 次 Connected/Disconnected 切换，最终 VPN service 完全停止。

### P1：必须先修

- [ ] `include/zerotier.go`：真实注册要求 `with_zerotier && with_gvisor`；stub 覆盖 `!with_zerotier || !with_gvisor`。
- [ ] `protocol/zerotier/routes.go`：让 LAN-local 路由参与最长前缀匹配，避免错误选择更宽网关路由。
- [ ] `protocol/zerotier/multicast_queue.go`：禁止 `VirtualNetworkConfig` 回调阻塞等待有界 multicast 队列。
- [ ] `protocol/zerotier/endpoint.go`：等待 Node 回调退出后再销毁 gVisor stack。
- [ ] `protocol/zerotier/stack.go`：`Attach(nil)` 必须真正清空 dispatcher，并防御 nil dispatcher。
- [ ] `protocol/zerotier/dialer.go`：关闭开始后拒绝新 Dial/Listen，并等待已进入调用退出。
- [x] NexBox `VpnService.kt`：IPv4 planet 地址排除 `/32`，IPv6 使用 `/128`（NexBox `f52f163`）。
- [ ] `protocol/zerotier/mactable.go`：为邻居缓存增加容量、TTL 和可接受源约束。
- [ ] `protocol/zerotier/multicast.go`：为每个本地 IPv4 订阅 broadcast MAC 加 host-byte-order IPv4 ADI。

### P2：同轮修复

- [ ] 配置应用失败时向 go-zt 返回失败，不得固定返回成功。
- [ ] 无活跃 endpoint 时状态 API 返回 `[]`，不得编码为 `null`。
- [ ] 相同 tag 替换时，旧 endpoint 只能删除指向自身的 registry 项。
- [ ] gVisor stack 部分初始化失败时完整销毁局部资源。
- [ ] planet-IP fallback 按 endpoint 独立判断。
- [ ] 关闭后禁止 packet enqueue，并确保最终 drain 不泄漏引用。

### 维护门禁

- [ ] 为 `with_zerotier,with_gvisor` 增加定向 build/test/Race CI；当前默认 CI tags 不包含 `with_zerotier`。
- [ ] 修复后重新执行本页全部构建与真机验收，再更新发布判定。
