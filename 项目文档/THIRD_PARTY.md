# 第三方依赖与权利

本项目没有内嵌第三方源码。`pyproject.toml` 固定运行时依赖：

| 依赖 | 版本 | 原权利与许可 | 使用方式 |
| --- | --- | --- | --- |
| [PyJWT](https://github.com/jpadilla/pyjwt) | 2.15.1 | José Padilla 等；[MIT 许可证](https://github.com/jpadilla/pyjwt/blob/master/LICENSE) | 外部安装；JWS 签名和声明校验 |
| [cryptography](https://github.com/pyca/cryptography) | 50.0.2 | Python Cryptographic Authority 与贡献者；[Apache-2.0 OR BSD-3-Clause](https://github.com/pyca/cryptography/blob/main/LICENSE) | 外部安装；RSA 公钥解析及测试签名 |

当前 Python 3.14 本地解析出的传递依赖还包括 `cffi==2.1.1`（MIT-0）和 `pycparser==3.0`（BSD-3-Clause）；它们各自的许可证文件随其**独立安装的发行包**提供。正式复验会在收据中记录精确解析版本。`build`、`setuptools` 和 `wheel` 仅用于 Build 下的构建环境，不随本项目运行包分发。未来若复制、打包或另行分发这些第三方组件，须再次核对对应版本的完整原许可证和通知；本项目的新代码 MIT 权利见 [LICENSE](LICENSE)。

