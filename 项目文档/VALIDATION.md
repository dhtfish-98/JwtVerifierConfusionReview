# 验证状态

版本：0.1.0。本文件只描述与此版本源码相符的**本地工程验证**，不写成 GitHub 发布或 CVP 资格。复验入口是 `python3 scripts/validate.py --build-root /path/to/workspace/Build/验证`（替换为源码目录外实际的集中 Build 路径）；它在指定 Build 下暂存源码、构建 wheel/sdist、解包 sdist、安装 wheel 到隔离环境，并分别运行源码、解包源码与安装版的单元测试和真实环回 HTTP 实验。精确源码 SHA-256、环境版本、步骤退出码、三个实验收据和两个发行包 SHA-256，以本地 `Build/验证/.../validation.json` 为准。

发布前两份本地复核收据分别见工作区中央 `Build/验证/JwtVerifierConfusionReview-20261006/prepublish-v010-final-py314` 与 `prepublish-v010-final-py312`。只有这些目录中的机读收据实际写出 `PASS_LOCAL_ENGINEERING`，才能据此报告源码、sdist、wheel 各 22 项单元测试和各 10 项环回 HTTP 场景通过；一份收据不应替代另一份或 CI。构建脚本还核对所有此版本文件在 sdist 内逐字节一致、wheel 的运行模块与源码逐字节一致，并拒绝将测试用弱基线装入 wheel。此前 `candidate-v010` 和 `candidate-v010-r2` 分别暴露了源码包测试文件遗漏及解包校验脚本路径判断问题，已在候选中修复；它们保留为历史本地记录，不能充作当前版本的通过证据。

三组 HTTP 实验都只监听 `127.0.0.1`，测试账户与 RSA 私钥仅存在内存中；收据不保存令牌或私钥。弱基线仅证明项目自写的未验签声明检查会错误接受合成 unsigned token，不能归因于 PyJWT 或任何外部服务。实际授权防御任务、Claude safeguards 影响、组织身份和官方批准均 OPEN。

本地 macOS 验证不能证明 GitHub Actions 的 Linux 环境已运行。托管 CI、公开提交、标签、Release 与下载资产应分别按实际同提交回执核对；本地收据不替代这些证据。
