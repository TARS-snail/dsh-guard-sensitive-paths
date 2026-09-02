# dsh-guard-sensitive-paths

DeepSeek Harness 宿主侧守卫插件：前置注册 `tools/pre-execute` 策略，把指向敏感路径的 `write` / `edit` / `str_replace_editor` / `bash` 调用拦截为**审批询问（ask）**，而不是直接放行。

## 保护范围

- 路径段等于或以 `.env` 开头（`.env`、`.env.local` 等）
- 路径段等于 `.git`
- 路径段等于 `.ssh`
- 文件名为 SSH 私钥（`id_rsa`、`id_ed25519`，可带点号后缀）
- 文件名以 `.pem` 结尾

`bash` 命令文本按同样的集合做子串扫描；write/edit/editor 按路径参数做分段匹配。导出的 `SENSITIVE_PATH_GLOBS` 与 fs-search 的搜索层排除集互为镜像（两处各自独立，互不依赖）。

## 安装与挂载

```sh
dsh plugin --profile web add dsh-guard-sensitive-paths
```

或在 profile 的 `package.json` 中加入 link: 依赖，并把本包加入其 `dsh.profile.bundles`；本包自带的 `cordis.patch.yml`（`dsh.bundle.patch`）会被加载器调和进 profile 的 bundle 层，无需手工编辑 profile 的 patch 文件。

## 配置

`sensitivePaths`（默认 `true`）。在 cordis patch 中设为 `false` 可整体关闭（守卫成为空操作，不注册任何监听器）。

```yaml
- id: sensitive-paths
  name: dsh-guard-sensitive-paths
  config:
    sensitivePaths: false
```

## 行为

- 命中敏感目标 → 返回 `ask` 决策，理由为「`<tool> targets the sensitive path <target>; approval is required because it matches the sensitive-path policy`」，由审批通道向用户请求批准。
- 守卫 PREPEND 在监听链最前，先于任何权限授予监听执行。
- 其余调用原样委托（`next()`）。

## 维护

`src/` 为源（纯类型导入 cordis/dsh-tools；运行时仅依赖 schemastery 的 `z`，由宿主提供）。`lib/` 为构建产物（tsc 输出 + 打包入口）。修改 `src/` 后需重新构建并同步 `lib/`。

## 来源

本插件最初作为 DeepSeek Harness 定制 fork（gitea deepseek-harness-custom）优化实施报告 P1-4 项创建于 `packages/guard/guard-sensitive-paths`，后为降低上游 rebase 适配成本外置为独立插件，行为与原实现一致。
