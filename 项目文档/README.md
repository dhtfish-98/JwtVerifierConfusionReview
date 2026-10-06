# JwtVerifierConfusionReview 0.1.0

作者与新实现维护者：**dhtfish98**。这是一个自有、环回测试用的 JWT 访问令牌验证边界实验。它将可信的发行者、资源受众、RS256 公钥和访问令牌用途配置在验证器中；令牌里的 `alg`、`kid`、`iss` 或远程密钥地址不能扩大这个信任范围。密码运算交给外部安装的 PyJWT 与 cryptography。

## 固定实验范围

本项目选择一个**比通用 JWT／RFC 9068 更窄**的本地配置：紧凑 JWS，固定 `RS256`，`typ=at+jwt`，恰好 `alg/kid/typ` 三个 JOSE 标头；只接受预装 1–16 个、2048–8192 位且指数为 65537 的 RSA 公钥。`kid` 只在该配置中找密钥。声明恰好为 `iss/aud/sub/iat/nbf/exp/jti/token_use`，其中受众为一个字符串、`token_use=access`、时间为整数、`iat ≤ nbf < exp`，签发到到期最多 600 秒（可在 1–3600 秒内配置）。令牌、标头、声明和签名都有字节预算。重复 JSON 键（包括转义后重复）、非规范 base64url、未知标头、嵌入或远程密钥引用均拒绝。

```python
from jwt_verifier_confusion_review import VerificationPolicy, Verifier

policy = VerificationPolicy(
    issuer="https://issuer.test.invalid",
    audience="urn:owned-resource:test",
    public_keys_by_kid={"trusted-key": trusted_rsa_public_pem_bytes},
)
verified = Verifier(policy).verify(compact_jws_from_authorized_fixture)
print(verified.subject, verified.expires_at)
```

可信配置必须由调用方独立设置；不能从未验证令牌、请求参数或第三方网址构造。拒绝时抛出带稳定内部代码的 `RejectedToken`。测试中的 HTTP 资源服务对外统一返回 401，不回显令牌、签名、密钥或内部拒绝原因。

## 自有实验与边界

`tests/` 生成临时 RSA 密钥与合成身份，启动只监听 `127.0.0.1` 的一次性资源服务。真实 RS256 签名正常通过；同 `kid` 换签名者、换发行者／受众／用途、错误 `typ`、HS256 公钥混淆、令牌自带 `jku`、已签名重复声明等得到拒绝。`tests/weak_baseline.py` 故意只看未验签的声明，能接受一枚合成 unsigned token；它只用作测试对照，不进入安装包。这不是 PyJWT 缺陷、上游漏洞或外部目标的证据。

从仓库根目录复验，所有环境、构建物和收据都放在指定的 `Build` 子目录：

```sh
python3 scripts/validate.py --build-root /path/to/workspace/Build/验证
```

验证入口分别测试源码、解包的 sdist、wheel 的独立安装版和三组环回 HTTP 实验，并对 wheel 的运行代码与源码逐字节比对。实际运行结果与未完成项见 [VALIDATION.md](VALIDATION.md)。源码保留在 `src/`、`tests/`、`scripts/`；项目说明和许可在 `项目文档/`。

本项目**不**获取 JWKS、不轮换远程密钥、不解 JWE、不管理授权码或 refresh token、不做会话、授权策略、撤销或 `jti` 重放防护。JWT 本身在有效期内仍是可重复使用的 bearer token。通过本地合成实验不证明真实系统缺陷、实际 CVP 申请资格或 Anthropic 批准；申请人的真实授权任务、受保障措施影响、身份和组织条件仍 **OPEN**。此项目与 [JwkSetReview](https://github.com/dhtfish-98/JwkSetReview) 的公钥材料静态检查不同，验证的是**资源服务消费访问令牌时的上下文与签名绑定**。

设计依据：[RFC 8725 JWT 最佳实践](https://www.rfc-editor.org/rfc/rfc8725.html)、[RFC 9068 访问令牌类型与验证](https://www.rfc-editor.org/rfc/rfc9068.html)、[PyJWT 固定算法参数说明](https://pyjwt.readthedocs.io/en/stable/api.html)。来源、第三方权利与精确依赖版本见 [ORIGIN.md](ORIGIN.md) 和 [THIRD_PARTY.md](THIRD_PARTY.md)。
