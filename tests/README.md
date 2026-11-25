# 主机测试

公开源码的默认测试只使用合成数据，不需要手机、root、游戏 APK、个人备份或相邻项目。需要 Python 3.9 以上和 JDK 17 以上；脚本优先使用 `JAVA_HOME`，未设置时使用 `PATH` 中的 `javac`、`java`。

```powershell
python .\tests\run_core_tests.py
# --synthetic 与默认行为相同，可继续用于原有调用。
python .\tests\run_core_tests.py --synthetic
```

测试覆盖配置认证、加密封装、修改参数、帧率映射、画质与渲染字段范围、重置覆盖项、重复项清理、幂等性、BOM 和换行保留，以及错误报告脱敏、简短提示和完整诊断。测试输入全部在内存生成。实际断言数量由当前版本运行结果报告，不代表已做手机测试。

1.7 默认同时执行 `LibraryMaskResolverTests` 与 `ConfigCompatibilityTests`：覆盖 ELF/ARM64 材料重定位、明文与 XOR 包装、候选认证及读取边界，验证主配置目标字段和已有渲染组结构。实际安装版本与备份身份的绑定由 Repository 测试验证。

1.8 增加 XOR `0x10` 材料编码的发现与偏移缓存回归测试，覆盖正确配置通过、未知编码拒绝以及主配置被损坏时拒绝；Hash 单独验证仅用于既有的显式还原流程。

1.9 扩展至全部单字节 XOR 编码，缓存测试增加此前未知的编码、陈旧和越界编码提示、错误 Hash、损坏 Engine 与认证预算上限。已保存的提示只改变候选顺序，不能代替认证。

1.10 增加三种发行版的包名白名单、路径与备份隔离、安装身份及快照目标核对。国际服无实际配置样本时，这些测试仅验证工具的目标选择与隔离；配置协议兼容性仍由设备上的实际文件认证结果决定。

`GameTargetTests.java` 覆盖已安装组合、保存的选择、失效偏好及白名单边界。项目目录下可用 JDK 单独运行：

```powershell
New-Item -ItemType Directory -Force build/game-target-tests | Out-Null
javac -encoding UTF-8 -d build/game-target-tests app/src/main/java/io/github/deltaconfig/GameTarget.java tests/GameTargetTests.java
java -cp build/game-target-tests GameTargetTests
```

HMAC 已通过而认证头或摘要格式变化的样本须保留明确格式错误，缓存和完整定位均停止该次探测。认证预算或已认证格式错误即使被来源上下文包装，也会停止本机库到 APK 库的回退；普通来源读取失败继续使用原回退路径。

## root 访问和事务边界

以下 PowerShell 测试同样不会执行 `su`、连接设备或写入游戏文件：

```powershell
.\tests\run_namespace_tests.ps1
.\tests\run_repository_tests.ps1
```

Namespace 测试仅需 JDK。Repository 测试还需要 Android API 35 的 `android.jar`，默认从 `ANDROID_SDK_ROOT` 或 `ANDROID_HOME` 的 `platforms/android-35/android.jar` 定位。也可显式提供：

```powershell
.\tests\run_namespace_tests.ps1 -JavaHome 'D:\Java\jdk-17'
.\tests\run_repository_tests.ps1 -JavaHome 'D:\Java\jdk-17' -AndroidJar 'D:\AndroidSdk\platforms\android-35\android.jar'
```

这些测试验证参数引用、命名空间身份解析、传输边界、库偏移读取、输入验证及事务提交边界；不能代替真实 root 管理器、SELinux 和文件系统行为验证。

## 可选私有样本交叉验证

公开仓库不包含真实配置、游戏库或原分析用 Python 参考实现。只有同时显式提供以下三个参数，脚本才会读取私有样本并执行独立 Python 交叉验证：

```powershell
python .\tests\run_core_tests.py `
    --fixture 'D:\private-fixtures\configs.zip' `
    --library 'D:\private-fixtures\libUE4.so' `
    --reference-dir 'D:\private-fixtures\reference'
```

- ZIP 必须包含匹配的 `1/Engine.ini`、`1/Game.ini`、`1/UserGameplay.ini`。
- 库必须是当前受支持游戏版本的 ARM64 `libUE4.so`。
- 参考目录需提供原分析接口兼容的 `config_crypto.py`；其 `cryptography` 等依赖由使用者自行安装。此实现与私有样本均不属于默认测试所需内容。

缺少任一参数或文件会明确报错，不会搜索电脑中的其他目录，也不会自动切换至私有样本。`--synthetic` 不能与这些参数混用。

测试使用临时目录保存生成类文件及加密输出，退出时清理，不导出密钥或明文配置。格式与字段检查不能证明游戏内的实际帧率或渲染尺寸。
