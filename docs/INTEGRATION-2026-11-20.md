# zguard 与 zharness 原生安全基础设施接入记录

日期：2026-11-20（Asia/Taipei）。

## 发布结果

zguard 0.1.0 和 zharness 0.6.0 已发布到 crates.io，并建立 GitHub Release。两份公开 crate 均已实际下载，核对 SHA-256 与包内 .cargo_vcs_info.json；并非仅依据版本列表判断发布成功。

| 包 | 发布源码提交 | 下载大小 | 发布入口 |
| --- | --- | ---: | --- |
| zguard 0.1.0 | `5cdd637edbb075f6611f88f8566e15de4b360cca` | 20,455 字节 | [crates.io](https://crates.io/crates/zguard/0.1.0) · [GitHub Release](https://github.com/LIghtJUNction/zguard/releases/tag/v0.1.0) |
| zharness 0.6.0 | `db4206d3b74e37d57ff052948962f55514081d4b` | 207,692 字节 | [crates.io](https://crates.io/crates/zharness/0.6.0) · [GitHub Release](https://github.com/LIghtJUNction/zharness/releases/tag/v0.6.0) |

公开包 SHA-256：

- zguard：`641d20929078aba7e9eb6ae9c33ae89d9b23d3a0f12f0eebb8fd05dacc93eb40`。
- zharness：`4a4aff31bc0430ef21ac873c24985ecaa5dbe559aa1090e0339bea82cd1b31ef`。

zharness 的 [正式发布运行 44716889702](https://github.com/LIghtJUNction/zharness/actions/runs/44716889702) 已完成且结论为 success。Linux、Windows、macOS 分别在 Rust stable 和 1.99.1 上通过原生验证，portability 与 publish 作业也通过。其 annotated tag v0.6.0 指向上述 db4206d 提交。

zguard 的 [正式运行 44713799452](https://github.com/LIghtJUNction/zguard/actions/runs/44713799452) 中，Linux、Windows、macOS 原生验证与 Cargo 发布通过，最后的 GitHub 附件步骤失败。随后使用与公开注册表完全相同的归档完成 GitHub Release，并读回附件状态与校验值。原运行保留失败历史；后续 [24890a7](https://github.com/LIghtJUNction/zguard/commit/24890a70ba2a5e4f283f3c31eb30721143ffd9b5) 修复归档查找和恢复流程，原发布标签未变更。

## 已实现的执行边界

zguard 把宿主授权决定放在工具或命令产生副作用之前。模型只能提出请求；规则、能力、审批和时钟由宿主提供。zharness 的 guarded 入口使用实际交给适配器的请求进行检查，只有允许结果可以进入适配器。

| 能力 | 实际行为 | 证据 |
| --- | --- | --- |
| 默认拒绝 | 空策略、未知名称均拒绝；工具与命令使用不同名称空间 | [zguard 使用说明](https://github.com/LIghtJUNction/zguard/blob/v0.1.0/README.md) |
| 确定性规则 | 名称精确且区分大小写；拒绝优先于审批，审批优先于允许；能力要求合并 | [核心验证记录](https://github.com/LIghtJUNction/zguard/blob/v0.1.0/docs/VALIDATION-2026-11-20.md) |
| 请求绑定审批 | 宿主签发进程内、不可复制的审批对象；绑定完整策略、上下文、调用 ID、工具字节或命令 argv/cwd；每次尝试消耗审批 | [安全约定](https://github.com/LIghtJUNction/zguard/blob/v0.1.0/SECURITY.md) |
| 有界调用 | 限制授权调用次数和单次输入字节；适配器失败不退回次数 | [zguard 使用说明](https://github.com/LIghtJUNction/zguard/blob/v0.1.0/README.md) |
| 执行前审计 | 记录不包含原始参数、调用名称、调用 ID 和输出的结构化授权决策事件；审计失败即拒绝 | [zharness 接入说明](https://github.com/LIghtJUNction/zharness/blob/db4206d3b74e37d57ff052948962f55514081d4b/GUARDRAILS.md) |
| 真正阻止副作用 | 拒绝、待审批及审计失败时，适配器调用计数保持为零，输出缓冲区不变 | [集成测试](https://github.com/LIghtJUNction/zharness/blob/db4206d3b74e37d57ff052948962f55514081d4b/tests/guard.rs) |

审批不是持久化签名凭据。宿主重建 Guard 时应分配新的会话 epoch，并提供一致单位的单调时钟。审批不能覆盖显式拒绝、能力不足或用尽的调用次数。审计接收器自行负责持久化、权限与保留期；NoAudit 是宿主明确选择的审计关闭方式。

## zharness 使用方式

zharness 0.6.0 精确依赖 zguard 0.1.0，且该依赖不是可选 feature；同时对齐 zcall 0.4.0、zplugin 0.3.1。应用可直接使用重新导出的 zharness::zguard。

新增入口：

- Prepared::execute_guarded 及 execute_guarded_with_hooks。
- Command::execute_guarded 及 execute_guarded_with_hooks。
- 实现既有 executor trait 的 GuardedExecutor 与 GuardedCommandExecutor。
- 工具返回 Error::Guard(Verdict)，命令返回 CommandError::Guard(Verdict)。

```rust
let result = prepared.execute_guarded(
    &mut executor,
    &mut output,
    Authorization::new(&mut guard, &mut audit, now),
)?;
```

guard 应跨调用保留，以维持预算和单调时钟检查；每次执行创建新的 Authorization。需要审批时，由宿主通过可信审批通道确认精确请求，再传入 with_approval(approval)。模型输入中的 approved: true 或 capabilities 字段不会授予权限。

[完整可运行示例](https://github.com/LIghtJUNction/zharness/blob/db4206d3b74e37d57ff052948962f55514081d4b/examples/guarded_execution.rs) 展示先拒绝模型伪造的审批字段，再经宿主审批执行一次。命令为 cargo run --locked --example guarded_execution。

## 验证和轻量性

| 验证范围 | 结果 |
| --- | --- |
| zguard 核心 | 26 项运行测试、3 项文档测试，其中 2 项编译失败测试验证审批对象不可复制和不可重复消费 |
| zharness 本地全 feature 集成 | 133 项运行测试，其中 17 项 guard 集成测试；15 项文档测试 |
| 静态与依赖验证 | 格式、严格 Clippy、依赖审计及 guard 示例通过；zguard 元数据确认零 Cargo 依赖 |
| 发布脚本恢复 | zguard 16 项、zharness 29 项 Python 发布测试通过 |
| no_std | zguard 裸机/Wasm 编译通过；zharness portability job 验证裸机/Wasm及不同 Rust 版本 guest/host |
| 原生平台 | 以本记录发布回执所列 Linux、Windows、macOS 原生作业为准；本地交叉编译不冒充平台执行 |

zguard 内核使用 no_std，禁止 unsafe，不使用 allocator，没有 Cargo 依赖。这些属性仅指内核，不涵盖宿主进程、执行器或审计接收器。

本地微基准在 Intel Core i9-12900HX、x86_64 Linux、Rust 1.100.0 上测量：3 条规则、10,000 次预热、1,000,000 次测量、NoAudit。单次运行均值为：策略预览 16.31 ns，授权并预留次数 17.36 ns，签发审批并授权 64.98 ns。Guard 值自身为 88 字节。借用的规则和输入缓冲区不计入该值大小；上述测量不包含实际审计 I/O、插件、模型或网络开销，也不是端到端 Agent 延迟保证。详见[原始验证记录](https://github.com/LIghtJUNction/zguard/blob/v0.1.0/docs/VALIDATION-2026-11-20.md)。

## 应用接入范围

应用通过新的 guarded 入口启用这些检查。原有 execute、execute_with_hooks、直接 call_text/call_bytes，以及原生插件加载和初始化，保留宿主授权责任。将 Router 作为 executor 传入 guarded 入口时，检查发生在按公开工具名路由之前。

该内核负责确定性的执行授权。身份认证、审批通道、参数和资源策略、路径规范化、网络限制、执行超时及 OS/Wasm 隔离由宿主实现。它不检测自然语言提示注入，也不将被允许的 shell 或本机插件变成沙箱。消费项目仍需验证自己的真实运行路径。

## Project Z 与下游状态

Project Z 已在聚合候选 [b54f083e2b7900c2f5c93ec93e26366526645095](https://github.com/LIghtJUNction/project-z/commit/b54f083e2b7900c2f5c93ec93e26366526645095) 登记 zguard，gitlink 指向已发布源码 5cdd637；同时更新 .gitmodules、Cargo 本地映射、catalog.json、项目目录和验收记录。

聚合协调者的实际回执记录 43 个仓库、62 个 Cargo package，sync/check 均退出 0，101 个递归子模块与固定源码相符。[聚合验收回执](https://github.com/LIghtJUNction/project-z/blob/b54f083e2b7900c2f5c93ec93e26366526645095/docs/reports/ui-unification-20261120/accepted-component-pins.md)

该登记仍在 coord/zgpui-propagation-20261120 候选，Project Z main 的整体合入等待既有套件最终固定版本与完整依赖解析验收。此快照内 zharness 仍固定 0.5.1；已发布的 0.6.0 需要随 zcall/SSMCP 后续消费批次更新。

SSMCP 0.10.21 正处于发布冻结。本次下游准备仅覆盖独立 checkout 中的 Cargo.toml、Cargo.lock 和 crates/zharness gitlink；冻结版本的源树与运行路径保持其原有状态。依赖升级不能替代运行路径接入：SSMCP 当前直接 call_text 的路径尚未迁入 guarded 入口，因此本记录不将其记为运行期安全接入完成。
