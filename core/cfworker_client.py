import random
import string
import time
import email as email_lib
from email import policy
from typing import Optional

import requests
from bs4 import BeautifulSoup

from core.mail_utils import extract_verification_code
from core.proxy_utils import request_with_proxy_fallback


class CfWorkerClient:
    """Cloudflare Worker 自建临时邮箱客户端

    API 说明：
    - 创建邮箱：POST /api/new_address  body={name, domain}  header: x-admin-auth
      返回 {jwt, address}
    - 查邮件：GET /api/mails?limit=10&offset=0  header: Authorization: Bearer <jwt>
      返回 {results: [...], count: N}，每封邮件的内容在 raw 字段（完整 MIME 格式）
    """

    def __init__(
        self,
        base_url: str = "",
        admin_password: str = "",
        domain: str = "",
        proxy: str = "",
        verify_ssl: bool = True,
        log_callback=None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_password = admin_password.strip()
        self.domain = domain.strip()
        self.verify_ssl = verify_ssl
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.log_callback = log_callback

        self.email: Optional[str] = None
        self.jwt_token: Optional[str] = None  # 每个邮箱独立的 JWT

    def set_credentials(self, email: str, password: str = None) -> None:
        """设置邮箱凭证

        对于刷新场景，password 参数实际传入的是 JWT token（存储在 mail_jwt_token 中）
        """
        self.email = email
        if password:
            self.jwt_token = password

    def _request(self, method: str, url: str, **kwargs) -> requests.Response:
        """发送请求"""
        self._log("info", f"📤 发送 {method} 请求: {url}")

        try:
            res = request_with_proxy_fallback(
                requests.request,
                method,
                url,
                proxies=self.proxies,
                verify=self.verify_ssl,
                timeout=kwargs.pop("timeout", 15),
                **kwargs,
            )
            self._log("info", f"📥 收到响应: HTTP {res.status_code}")
            if res.status_code >= 400:
                try:
                    self._log("error", f"📄 响应内容: {res.text[:500]}")
                except Exception:
                    pass
            return res
        except Exception as e:
            self._log("error", f"❌ 网络请求失败: {e}")
            raise

    def register_account(self, domain: Optional[str] = None) -> bool:
        """创建新的临时邮箱"""
        try:
            use_domain = domain or self.domain
            prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))

            body = {"name": prefix}
            if use_domain:
                body["domain"] = use_domain
                self._log("info", f"📧 使用域名: {use_domain}")

            res = self._request(
                "POST",
                f"{self.base_url}/api/new_address",
                json=body,
                headers={"x-admin-auth": self.admin_password},
            )

            if res.status_code == 200:
                data = res.json()
                jwt = data.get("jwt")
                address = data.get("address")
                if jwt and address:
                    self.email = address
                    self.jwt_token = jwt
                    self._log("info", f"✅ CF Worker 邮箱创建成功: {self.email}")
                    return True
                else:
                    self._log("error", "❌ 响应中缺少 jwt 或 address 字段")
                    return False
            elif res.status_code in (401, 403):
                self._log("error", "❌ CF Worker 认证失败 (admin_password 无效)")
                return False
            else:
                self._log("error", f"❌ CF Worker 邮箱创建失败: HTTP {res.status_code}")
                return False

        except Exception as e:
            self._log("error", f"❌ CF Worker 注册异常: {e}")
            return False

    def login(self) -> bool:
        """登录（CF Worker 不需要登录，JWT 在创建时获取）"""
        return True

    def _parse_html_from_raw(self, raw_content: str) -> Optional[str]:
        """从 MIME 格式的 raw 邮件中提取 HTML 正文"""
        try:
            msg = email_lib.message_from_string(raw_content, policy=policy.default)
            for part in msg.walk():
                if part.get_content_type() == 'text/html':
                    return part.get_content()
        except Exception as e:
            self._log("error", f"❌ 解析 MIME 邮件失败: {e}")
        return None

    def fetch_verification_code(self, since_time=None) -> Optional[str]:
        """获取验证码"""
        if not self.email:
            self._log("error", "❌ 邮箱地址未设置")
            return None

        if not self.jwt_token:
            self._log("error", "❌ JWT Token 未设置（无法读取邮件）")
            return None

        try:
            self._log("info", "📬 正在拉取 CF Worker 邮件列表...")

            res = self._request(
                "GET",
                f"{self.base_url}/api/mails",
                params={"limit": 10, "offset": 0},
                headers={"Authorization": f"Bearer {self.jwt_token}"},
            )

            if res.status_code in (401, 403):
                self._log("error", "❌ JWT Token 认证失败（可能已过期）")
                return None

            if res.status_code != 200:
                self._log("error", f"❌ 获取邮件列表失败: HTTP {res.status_code}")
                return None

            data = res.json()
            mails = data.get("results", [])

            if not mails:
                self._log("info", "📭 邮箱为空，暂无邮件")
                return None

            self._log("info", f"📨 收到 {len(mails)} 封邮件，开始检查验证码...")

            for idx, mail in enumerate(mails, 1):
                raw = mail.get("raw", "")
                if not raw:
                    continue

                # 方法1：从 MIME 解析 HTML，找 verification-code 标签
                html = self._parse_html_from_raw(raw)
                if html:
                    # 先尝试 Gemini 专用的 verification-code 标签
                    soup = BeautifulSoup(html, "html.parser")
                    span = soup.find("span", class_="verification-code")
                    if span:
                        code = span.get_text().strip()
                        if len(code) == 6:
                            self._log("info", f"✅ 找到验证码（HTML标签）: {code}")
                            return code

                    # 再用通用提取逻辑
                    code = extract_verification_code(html)
                    if code:
                        self._log("info", f"✅ 找到验证码（HTML内容）: {code}")
                        return code

                # 方法2：从 raw 纯文本中用通用提取
                code = extract_verification_code(raw)
                if code:
                    self._log("info", f"✅ 找到验证码（raw内容）: {code}")
                    return code

            self._log("warning", "⚠️ 所有邮件中均未找到验证码")
            return None

        except Exception as e:
            self._log("error", f"❌ 获取验证码异常: {e}")
            return None

    def poll_for_code(
        self,
        timeout: int = 120,
        interval: int = 4,
        since_time=None,
    ) -> Optional[str]:
        """轮询获取验证码"""
        max_retries = max(1, timeout // interval)
        self._log("info", f"⏱️ 开始轮询验证码 (超时 {timeout}秒, 间隔 {interval}秒, 最多 {max_retries} 次)")

        for i in range(1, max_retries + 1):
            self._log("info", f"🔄 第 {i}/{max_retries} 次轮询...")
            code = self.fetch_verification_code(since_time=since_time)
            if code:
                self._log("info", f"🎉 验证码获取成功: {code}")
                return code

            if i < max_retries:
                self._log("info", f"⏳ 等待 {interval} 秒后重试...")
                time.sleep(interval)

        self._log("error", f"⏰ 验证码获取超时 ({timeout}秒)")
        return None

    def _log(self, level: str, message: str) -> None:
        """日志回调"""
        if self.log_callback:
            try:
                self.log_callback(level, message)
            except Exception:
                pass
