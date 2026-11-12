# 证据保全库

保存内容寻址对象与案件保管链，支持交接、双人封存、保留和档案包校验。链摘要只证明本地完整性，不代替外部签名或可信时间。

Python 3.11 标准库与 SQLite 即可运行。数据、时钟和文件均在本地，不需要服务凭据。示例只使用合成记录。

## 运行

在仓库根目录执行：

```sh
python -m sealvault replay fixtures/sealing.json
python -m examples.context
python -m unittest discover -s tests -v
python -m compileall -q sealvault examples
```

示例使用内存或临时目录，不会改动持久台账。`examples/context.json` 记录一组可重复导入的业务输入，字段与时间口径见 `examples/数据说明.md`。`examples.context` 检查数据并调用现有产品入口；它只展示原有业务数据，不计算分析结论。

`tests` 覆盖现有业务生命周期、非法输入、版本和完整性边界，另有示例导入回归。完整测试和上述演示可在一次短终端会话中执行。

## 流程分析（sealvault.process）

在保管链与交接记录之上增加只读流程分析，回答“该在哪个环节补人”，不读取或输出任何证据内容（条目、摘要、原因文本等一律不进入分析快照，落库前由字段白名单 `enforce_privacy` 强制拦截）。

- 队列按案件**首次创建时间**窗口圈定；观察截止 `cutoff` 与每个案件的保管链头 `heads` 在分析时固定，链头不匹配或时间倒退进入硬诊断并排除出统计，截止仍开放的交接属于观察性诊断，案件仍留在风险集。
- 活动映射：创建、交接提出/接受/拒绝/取消、派生的“重新进入可编辑（editable_resumed）”、封存清单准备与封存，均带时间与链序号；同一时刻按链序处理。重试、拒绝、再进入保留为返工，不并入首次通过。
- 交接等待严格按 `handoff_id` 配对，开放中的等待以截止时间收口，绝不会拿下一条任意事件当结束。
- 输出实际活动路径及案件数、转移频次、各环节（办理、交接等待、返工、封存）完成用时、仍在等待时长，并把交接等待与案件总周转分开统计；自然时长与营业时长并列。
- 营业日历可配置工作日（周一=0…周日=6）、每日营业区间（左闭右开）、固定时区偏移与假日，跨夜、周末和假日的营业时长单独计算；日历版本与指纹随分析固定。
- 截止未封存案件进入风险集并右删失，给出 Kaplan–Meier 完成曲线、逐时点风险集/事件/删失数和可估计分位；中位数未达到时 `median_reached=false` 且 `median=null`，不用已完成样本均值代替。
- 角色对比按持有人时间区间分段归属，区间互不重叠，同一案件不会全程重复计给每个角色；交接等待归属接收方角色。
- 分析快照通过 `analysis.save` 不可变保存（同内容幂等、同 ID 不同内容拒绝），后来的封存不会改写旧分析。每个统计项都带 `case_id/handoff_id/sequence/时间`，可回溯到具体链事件。

```sh
python -m examples.process_demo
python -m unittest tests.process.test_calendar tests.process.test_analytics tests.process.test_demo -v
```

诊断代码：`chain_invalid`、`time_reversal`、`time_invalid`、`head_mismatch`、`chain_empty`、`missing_creation`、`duplicate_handoff_proposal`、`duplicate_handoff_decision`、`orphan_handoff_decision` 为硬诊断（排除出聚合）；`handoff_open_at_cutoff` 为观察性诊断（保留在风险集）。

## 容器

```sh
docker build -t local/sealvault .
docker run --rm --network none local/sealvault
docker run --rm --network none local/sealvault python -m examples.context
```

镜像构建完成后运行和测试不下载文件。持久化使用各自命令的本地路径参数；具体操作及参数可通过 `python -m sealvault --help` 查询。第三方依赖清单为空。
