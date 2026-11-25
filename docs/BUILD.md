# 构建与验证

项目使用原生 Android API 和 Java 8 语法，无 Gradle、Maven、AndroidX 或构建时网络依赖。公开源码可以在 Windows 上使用 JDK 17 和官方 Android SDK 构建；不需要相邻项目、私有游戏样本或额外编译辅助 JAR。

## 标准工具链

准备以下工具：

- 完整 JDK 17，包含 `javac`、`java`、`jar` 和 `keytool`。
- Android SDK Platform 35：`platforms/android-35/android.jar`。
- Android SDK Build Tools 35.0.0：`build-tools/35.0.0/`。

使用 Android SDK Manager 安装对应平台与构建工具；若已安装官方命令行工具，可运行：

```powershell
sdkmanager.bat 'platforms;android-35' 'build-tools;35.0.0'
```

在仓库根目录设置本机路径后构建：

```powershell
$env:JAVA_HOME = 'D:\Java\jdk-17'
$env:ANDROID_SDK_ROOT = 'D:\AndroidSdk'
.\build.ps1
```

`ANDROID_HOME` 也可用于指定 SDK。未设置 `JAVA_HOME` 时，构建脚本还会检查 `PATH` 中的 `javac.exe`。脚本不下载工具、不安装软件、不操作 Android 设备。

也可将 SDK 放在项目的 `toolchain/` 下。默认工具链目录为 `./toolchain`，可显式替换：

```powershell
.\build.ps1 -ToolchainPath 'D:\AndroidSdk'
```

标准 SDK 目录布局为：

```text
toolchain/
  platforms/android-35/android.jar
  build-tools/35.0.0/
    aapt2.exe
    zipalign.exe
    lib/d8.jar
    lib/apksigner.jar
```

JDK 可通过 `JAVA_HOME`、`PATH` 提供，也可放入工具链根目录的 `jdk-*` 子目录。显式 `-ToolchainPath` 中存在 JDK 时优先使用其中的 JDK，其余情况优先 `JAVA_HOME`。

## 已有离线布局

显式传入工具链路径时，也兼容早期离线目录结构：

```text
<toolchain>/
  jdk-<version>/bin/
  android-35/android.jar
  android-15/              # 目录名沿用旧布局，内容须是 Build Tools 35.0.0
    aapt2.exe
    zipalign.exe
    lib/d8.jar
    lib/apksigner.jar
```

工具链可位于任意目录。仓库不提供、也不会隐式访问其他项目的工具链。旧目录中的 `javac-lambda-bootstrap.jar` 不再需要。

## Java 编译与 Lambda

构建使用 `javac --release 8 -classpath <android.jar>`，JDK 的 Java 8 API 提供编译 Lambda 所需的 bootstrap 方法声明，Android 类型来自官方 SDK。D8 随后使用 `--lib <android.jar> --min-api 26` 将类文件转换为 Android DEX。

早期使用 `-bootclasspath android.jar` 时，SDK 公开桩中的 `LambdaMetafactory` 缺少 javac 所需声明，因此曾额外使用一个仅包含该 JDK 类的辅助 JAR。当前编译方式不依赖它，也不把 JDK 类放入 APK。JDK 17、API 35 与 Build Tools 35.0.0 的全项目编译和 D8 转换已在开发机验证；手机运行仍需另行验证。

## 输出与签名

默认版本为 1.10，版本代码为 11：

```text
dist/鼠鼠工具箱-1.10.apk
dist/build-verification.json
dist/apk-signature-verification.txt
dist/apk-package-verification.txt
```

可通过 `-VersionName` 和 `-VersionCode` 显式指定其他版本。`build/` 保存每次独立构建的中间文件。源码打包脚本可单独运行：

```powershell
.\package-source.ps1
```

首次构建会在 `signing/` 内生成本机使用的 PKCS#12 签名及随机密码文件；后续构建复用原文件，不替换现有身份。请妥善保存这两个文件，以便覆盖安装自己的更新。不同开发者首次构建会生成不同签名；自行构建的 APK 无法直接覆盖其他签名版本。

**不要提交或上传 `signing/`、密码、私钥、个人配置和备份。** 公开源码及源码包应排除 `signing/`、`build/`、`dist/`、私有样本和测试生成目录。

## 检查范围

构建自动检查 javac、D8、源文件构建期间未变化、APK 签名、ZIP 对齐和包元数据；`build-verification.json` 记录 APK 与构建源文件的 SHA-256。

主机测试说明见 [tests/README.md](../tests/README.md)。默认合成测试只需 Python 标准库与 JDK；Repository 测试额外使用 SDK `android.jar`，不会执行 root 命令或写入设备。真实游戏样本测试仅在显式提供输入时启用。

主机检查不能证明手机 root 授权、存储挂载、SELinux 或游戏运行行为。设备验证应分别记录版本识别、读取、错误拒写、备份一致性、配置认证、回滚及游戏实际表现，不得将未经实测的项目报告为通过。
