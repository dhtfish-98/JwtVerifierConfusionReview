# 来源与归属

本仓 `src/`、`tests/`、`scripts/` 的新实现作者为 **dhtfish98**。研究问题参考 [PyJWT 的固定源码快照](https://github.com/jpadilla/pyjwt/tree/b5bd6fe6d7ac0370ba90557c7a1e3d50a9414572)及 [PyJWT 当前 API 文档](https://pyjwt.readthedocs.io/en/stable/api.html)；那个源码提交仅固定所读范围，不是本实验发现或修复上游漏洞的证据。本项目没有复制、改署名或分发 PyJWT／cryptography 源码。运行时通过包管理器安装独立的第三方库，精确版本写在 `pyproject.toml`。

安全边界取自 [RFC 8725 §3.1](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.1) 的算法固定要求和 [RFC 9068 §4](https://www.rfc-editor.org/rfc/rfc9068.html#section-4) 的访问令牌验证要求；本项目只实现明确声明的子集。`tests/weak_baseline.py` 是本项目自写的故意弱化对照，不可归因于 PyJWT 或 RFC 作者。

本地源码与实验不能证明真实应用漏洞、外部目标授权、Claude safeguards 影响、申请资格或官方批准；这些事实须来自申请人实际任务的独立证据。

