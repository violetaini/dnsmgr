# 可选的统一登录接入

本 fork 提供可选的本机身份代理适配器，不在 DNS 系统内维护另一套 OAuth 令牌。未启用时，原登录流程保持原状。启用后，浏览器只能通过统一登录；原密码、TOTP、域名快捷登录及安装入口关闭。身份服务不可用时拒绝后台访问。

## 权限与机器任务

每个获准的统一账号 subject 必须明确绑定到一个已经存在的 DNS 用户 ID，同时具备统一账号的 admin/root 角色。不会按用户名自动创建管理员。DNS 用户被禁用后立即失效，域名权限仍从原用户的 permission 表读取。用户、密码哈希、API Key、域名、证书和部署任务均不迁移。

原有 `/api/` 签名认证及 `/cron` 等任务认证继续独立工作，不要求浏览器登录。SSO 登录不能代替 API 签名，也不能通过请求头指定一个用户来冒充身份。

## 部署条件

1. 在本机部署受信任的身份代理，只监听 `127.0.0.1:9788`。适配器仅调用其 `dns/start`、`dns/callback`、`dns/validate`、`dns/logout`，使用独立随机 RPC 密钥。
2. 在身份服务登记独立客户端，精确回调为 `https://dns.example.com/sso/callback`。代理使用授权码、PKCE、state、nonce 和统一会话核验。访问及刷新令牌留在代理中。
3. 在项目根目录（public 的上一级）创建 `.sso.json`。文件由 root 管理，仅 PHP 用户组可读，权限 0640，不得提交到仓库或放进升级包：

   ```json
   {
     "origin": "https://dns.example.com",
     "key": "替换为至少32字符的随机RPC密钥",
     "bindings": { "明确批准的统一账号subject": 1000 },
     "accountUrl": "https://identity.example.com/portal"
   }
   ```

4. 同时创建根目录标记 `.sso-required`。如果配置损坏或丢失，该标记会阻止退回原密码登录。PHP 用户必须可读这两个文件。
5. Nginx 的 PHP 配置应设置 `fastcgi_intercept_errors off`，避免把 API 认证错误替换成登录页。保留现有可信来源 IP 处理，不在 PHP 内相信用户自填的转发头。
6. 核验 `/login` 的统一登录按钮、完整回调、原 API 签名、后台列表、退出和无 CSRF 的拒绝行为。

浏览器会话使用 Secure、HttpOnly、Host-only Cookie。后台写请求必须有固定 Origin 和当前会话的 CSRF 凭据；原页面的 Ajax、fetch 及表单由同源 JS 适配。`/logout` 展示确认表单，POST 后统一退出；密码和两步验证移到账号中心。

## 升级与恢复

从本 fork 的正式 Release 升级，保留 `.sso.json` 和 `.sso-required`。SSO 适配器、AuthUser 接入点及回归测试同时维护在 `patches/customizations`；上游同步及稳定包构建检查该接入点，冲突或测试失败时停止。

不要直接使用原上游覆盖包：它不包含此接入点，可能恢复原登录。升级前备份数据库、配置与网站代码；升级后运行 `php tests/SsoBridgeTest.php` 并核验公开登录及签名 API。身份服务与本机代理独立部署，第三方更新无需接触它们的私钥或客户端密钥。回滚需由服务器管理员显式恢复备份，不提供网页免认证应急入口。
