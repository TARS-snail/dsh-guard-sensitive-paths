# dsh-guard-sensitive-paths

一个 DeepSeek Harness（DSH）插件（bundle）：宿主侧**前置**注册 `tools/pre-execute` 策略，把指向敏感路径的 `write` / `edit` / `str_replace_editor` / `bash` 调用拦截为**审批询问（ask）**——命中时调用不会直接执行，而是请求用户批准；没有审批通道的自动化按失败关闭。

> 本插件是纯审批策略：不修改任何会话行为，只把命中敏感目标的调用变成一次审批交换。`grep` / `glob` 对同一敏感集合的**搜索排除**由搜索层（`@deepseek-ai/dsh-tool-fs-search`）始终开启地完成，与该插件的配置无关。

## 保护范围

| 类别 | 匹配规则 | 示例 |
|---|---|---|
| 环境变量文件 | 路径段以 `.env` 开头 | `.env`、`.env.local` |
| Git 元数据 | 路径段等于 `.git` | `.git/config` |
| SSH 私钥 | 文件名为 `id_rsa` / `id_ed25519`（可带点号后缀） | `id_rsa`、`id_ed25519.pub` |
| 证书 | 文件名以 `.pem` 结尾 | `server.pem` |
| SSH 目录 | 路径段等于 `.ssh` | `.ssh/id_ed25519` |

- `write` / `edit` 检查 `file_path`、`str_replace_editor` 检查 `path`，统一按**路径段**匹配（先归一化反斜杠）。
- `bash` 对**命令文本**按同一集合做子串扫描：命令里只要出现 `.env`、`.git/`、`id_rsa`、`id_ed25519`、`*.pem`、`.ssh/` 等名字就会触发询问。
- 其余工具原样放行。

## 安装

本包符合 DSH bundle 规范：`package.json` 声明 `dsh.bundle.patch`，指向随包发布的 `cordis.patch.yml`（注册 `id: sensitive-paths`）。`dsh plugin` 检测到 `dsh.bundle` 后会自动把它追加进该 profile 的 `dsh.profile.bundles` 层列表，重启该 profile（如 `dsh web`）后生效。

### 从 GitHub 安装

```sh
dsh plugin --profile web add github:TARS-snail/dsh-guard-sensitive-paths
```

### 从本地目录安装（开发/自用）

```sh
dsh plugin --profile web add /path/to/dsh-guard-sensitive-paths
```

### 验证

```sh
dsh --profile web --dump-config
# 生效的配置里应能看到 id 为 sensitive-paths 的一行（name: dsh-guard-sensitive-paths）
```

## 配置

默认零配置即开启。在 profile 的 `cordis.patch.yml`（用户层）中按 id 覆盖：

```yaml
- id: sensitive-paths
  name: dsh-guard-sensitive-paths
  config:
    sensitivePaths: false
```

| 字段 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `sensitivePaths` | boolean | `true` | 为 `false` 时守卫整体关闭：不注册任何监听器，成为空操作 |

## 工作原理

- 守卫以 **PREPEND** 方式注册在监听链最前，先于任何权限授予等其它 `tools/pre-execute` 监听执行；命中敏感目标即返回 `ask` 决策，理由为「`<tool> targets the sensitive path <target>; approval is required because it matches the sensitive-path policy`」。
- 未命中的调用经 `next()` 原样委托，不产生任何延迟或副作用。
- 导出的 `SENSITIVE_PATH_GLOBS` 常量与搜索层的排除 globs 互为镜像，两处各自独立实现、互不依赖（守卫匹配用分段规则，搜索层匹配用 glob 排除 + 路径二次过滤）。

## 开发与维护

- `src/` 为源（仅类型导入 cordis / dsh-tools；运行时仅依赖 schemastery 的 `z`，由宿主提供）。
- `lib/` 为构建产物（tsc 输出 + 打包入口），随包发布；修改 `src/` 后需重新构建并同步 `lib/`。
- 测试在 `tests/sensitive-paths.spec.ts`（`isSensitivePath` 单测 + 真实组合下 pre-execute 返回 ask 的行为测试）。

## 许可证

MIT
