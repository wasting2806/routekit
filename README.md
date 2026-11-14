# Routekit

以 [Johnshall 的 sr_top500_banlist_ad](https://github.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/blob/release/sr_top500_banlist_ad.conf) 为基础，补充持续维护的 AI 和 GitHub 域名，每天自动合并。保留上游广告过滤与代理分流，并固定以下 Tailscale 规则：

```ini
IP-CIDR,10.10.10.30/32,TAILSCALE,no-resolve
IP-CIDR,192.168.1.0/24,TAILSCALE,no-resolve
```

从 `bypass-tun` 移除覆盖它们的 `10.0.0.0/8`、`192.168.0.0/16`，更新地址指向本仓库。除此之外的 General 配置、URL Rewrite、MITM 设置保持原样，`skip-proxy` 不改。配置不存储节点订阅、密码、证书或 Tailscale 认证密钥。公开发布时，上面的内网路由地址也会公开；它们不包含访问凭据。

## 整合范围

| 来源 | 用途 |
| --- | --- |
| Johnshall / sr_top500_banlist_ad | 基础广告过滤、GFWList 分流、Telegram 等已有规则 |
| [v2fly / domain-list-community](https://github.com/v2fly/domain-list-community) 的 openai、anthropic、google-deepmind | ChatGPT/Sora、Claude、Gemini/AI Studio/NotebookLM 等域名缺口 |
| 同一来源的 github，以及其引用的 github-copilot、npmjs | GitHub 下载、容器镜像、Copilot、npm 域名缺口 |

原规则只删除完全相同的重复行，保留第一次出现的位置和所有其他规则的顺序。补充列表展开 include 后，仅转换域名和完整域名规则；跳过标注 `@ads`、`@telemetry` 的条目，跳过已有域名后缀或关键词覆盖的条目，再按后缀去重。补充规则放在原规则之后、`FINAL` 之前，保持已有广告拒绝和明确直连规则的优先级。

不再叠加第二套大型广告或 GFW 列表；不把整片云服务商 ASN/IP 段加入代理。本次初始合并删除 68 条完全重复规则，仅新增 73 条域名规则；相较于已加入两条 Tailscale 规则的版本，规则总数净增 5 条。上游已经覆盖的 Google、YouTube、Telegram 等无需重复加入。

补充列表采用域名匹配，不转换正则表达式和关键词；初始版本跳过 10 条广告/遥测条目和 1 条 OpenAI Azure WebPubSub 正则。这不等于新增拦截这些遥测域名，最终行为仍由基础配置决定。每次生成的文件头记录实际跳过数量。规则能减少漏分流，节点地址或协议被封锁仍需节点侧处理。

## 手机使用

在 Shadowrocket 的配置页面添加以下远程配置，下载后选择使用：

```text
https://raw.githubusercontent.com/wasting2806/routekit/main/sr_top500_banlist_ad.conf
```

保留手机已有代理节点，开启已登录的 Tailscale；若当前版本有“使用 Tailscale 子网”，需启用。重新连接 VPN，再用 Termius 连接 operator 的 `10.10.10.30:22` 或 J1900 后方已有授权的设备。

后续在这份远程配置上更新，地址固定指向 Routekit。仓库自动生成新版本后，手机仍需下载更新；可使用客户端提供的远程配置自动更新选项，或手动点更新。仓库定时任务不会主动修改手机上的配置。

分流规则不扩大 tailnet 或网关防火墙权限。当前手机的 J1900 侧授权为 `192.168.1.81:22`；子网内其他访问仍需对应服务的准入。不要将存储地址 `10.10.20.30` 用作手机 SSH 目标。

## 更新与验证

GitHub Actions 每天 UTC 01:23（北京时间 09:23）以及手动触发时，取得基础上游 release 和域名上游 master 的当前提交，再从各自固定提交下载配置与域名文件。生成文件头记录提交、每个源文件的 SHA-256、原作者、修改范围与 MIT 许可全文。完整生成、校验成功才原子替换本地文件并提交；任一下载、许可证、格式或校验异常都会中止，保留上一版。行数相对上一版减少超过 20% 或增加超过 25% 也会停下，需人工审查上游变化。

工作流仅使用标准 GitHub 托管运行器；[公开仓库可免费运行](https://docs.github.com/en/billing/concepts/product-billing/github-actions)，不需要部署服务器或添加密钥。GitHub 定时任务可能延迟，且[公开仓库连续 60 天无活动时可能自动停用定时任务](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)；日常上游同步通常会产生提交，但并非永久运行保证。查看 Actions 的实际结果；停用后可重新启用并手动运行。

Python 3.10+ 标准库，无第三方依赖。离线检查：

```bash
python3 -m unittest -v
python3 update.py
```

联网更新只改本地生成文件，不自动推送：

```bash
python3 update.py --update
```

验证涵盖定制规则优先级、TUN 排除项、更新地址、源格式、域名展开与去重、拒绝规则优先级，以及失败时上一版不被覆盖；手机真实连通性需在导入后验证。恢复时先禁用更新工作流，避免下一次定时任务重新生成；再用 Git revert 撤销具体生成文件的更新并重新下载，或在手机切回保留的原配置。修正生成逻辑并验证后可重新启用工作流。

本项目采用 engineering-standard 1.0.0，固定提交 `09f93fd9415b0ddeaec8843273cbaf3d8772c603`；主仓为 GitHub `wasting2806/routekit`，开发目录为 `~/src/routekit`。上游按只读版本取得，不向上游推送。

## 来源与许可

原规则作者为 Moshel、h2y、Johnshall 及上游贡献者；本仓库修改者为 wasting2806。保留上游署名和 [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 许可；本仓库的定制内容采用相同许可，详见 LICENSE。补充域名来自 v2fly/domain-list-community，保留 V2Ray 的 MIT 署名与许可全文，见 [licenses/v2fly-MIT.txt](licenses/v2fly-MIT.txt)；生成配置中也附有该许可。基础配置原有的 AppleNews 远程 RULE-SET 引用保持不变，由该上游维护。
