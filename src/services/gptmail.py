"""
GPTMail 临时邮箱服务实现 (mail.chatgpt.org.uk)
免费临时邮箱服务，无需 API Key
"""

import re
import os
import json
import time
import base64
import random
import logging
from typing import Optional, Dict, Any, List
from pathlib import Path

from curl_cffi import requests as cffi_requests

from .base import BaseEmailService, EmailServiceError, EmailServiceType
from ..config.constants import OTP_CODE_PATTERN


logger = logging.getLogger(__name__)


# Chrome 指纹配置
_CHROME_PROFILES = [
    {
        "major": 131, "impersonate": "chrome131",
        "build": 6778, "patch_range": (69, 205),
        "sec_ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    },
    {
        "major": 133, "impersonate": "chrome133a",
        "build": 6943, "patch_range": (33, 153),
        "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    },
    {
        "major": 136, "impersonate": "chrome136",
        "build": 7103, "patch_range": (48, 175),
        "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
    },
    {
        "major": 142, "impersonate": "chrome142",
        "build": 7540, "patch_range": (30, 150),
        "sec_ch_ua": '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
    },
]


def _random_chrome_version():
    """随机选择 Chrome 版本"""
    profile = random.choice(_CHROME_PROFILES)
    major = profile["major"]
    build = profile["build"]
    patch = random.randint(*profile["patch_range"])
    full_ver = f"{major}.0.{build}.{patch}"
    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full_ver} Safari/537.36"
    return profile["impersonate"], major, full_ver, ua, profile["sec_ch_ua"]


class GPTMailService(BaseEmailService):
    """
    GPTMail 临时邮箱服务 (mail.chatgpt.org.uk)
    
    特点：
    - 免费，无需 API Key
    - 使用 JWT token 进行认证
    - 支持 Chrome impersonate
    - 内置域名黑名单机制
    """

    # 类级别的黑名单（所有实例共享）
    _banned_domains: set = set()
    _banned_domains_file: Optional[str] = None

    def __init__(self, config: Dict[str, Any] = None, name: str = None):
        """
        初始化 GPTMail 服务

        Args:
            config: 配置字典，支持以下键:
                - base_url: API 基础地址 (默认: https://mail.chatgpt.org.uk)
                - timeout: 请求超时时间 (默认: 30)
                - max_retries: 最大重试次数 (默认: 5)
                - poll_interval: 邮件轮询间隔 (默认: 3.0)
                - proxy_url: 代理 URL
                - banned_domains_file: 黑名单文件路径
            name: 服务名称
        """
        super().__init__(EmailServiceType.GPTMAIL, name)

        # 默认配置
        default_config = {
            "base_url": "https://mail.chatgpt.org.uk",
            "timeout": 30,
            "max_retries": 5,
            "poll_interval": 3.0,
            "proxy_url": None,
            "banned_domains_file": "data/gptmail_banned_domains.txt",
        }

        self.config = {**default_config, **(config or {})}
        
        # Chrome 指纹
        self.impersonate, self.chrome_major, self.chrome_full, self.ua, self.sec_ch_ua = _random_chrome_version()

        # 创建 HTTP 会话
        self.session = cffi_requests.Session(impersonate=self.impersonate)
        
        # 配置代理
        if self.config.get("proxy_url"):
            self.session.proxies = {
                "http": self.config["proxy_url"],
                "https": self.config["proxy_url"]
            }

        # 设置默认请求头
        self.session.headers.update({
            "User-Agent": self.ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "sec-ch-ua": self.sec_ch_ua,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        })

        # 状态变量
        self._email_cache: Dict[str, Dict[str, Any]] = {}
        self._browser_token: Optional[str] = None

        # 加载黑名单
        self._load_banned_domains()

    @classmethod
    def _load_banned_domains(cls):
        """从文件加载黑名单"""
        if cls._banned_domains_file is None:
            # 尝试从环境变量或默认路径获取
            data_dir = os.environ.get("APP_DATA_DIR", "data")
            cls._banned_domains_file = os.path.join(data_dir, "gptmail_banned_domains.txt")
        
        try:
            if os.path.exists(cls._banned_domains_file):
                with open(cls._banned_domains_file, "r", encoding="utf-8") as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith("#"):
                            cls._banned_domains.add(domain)
                logger.info(f"已加载 {len(cls._banned_domains)} 个黑名单域名")
        except Exception as e:
            logger.warning(f"加载黑名单失败: {e}")

    @classmethod
    def _save_banned_domain(cls, domain: str):
        """保存黑名单域名到文件"""
        if cls._banned_domains_file is None:
            data_dir = os.environ.get("APP_DATA_DIR", "data")
            cls._banned_domains_file = os.path.join(data_dir, "gptmail_banned_domains.txt")
        
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(cls._banned_domains_file), exist_ok=True)
            
            domain = domain.lower().strip()
            if domain not in cls._banned_domains:
                cls._banned_domains.add(domain)
                with open(cls._banned_domains_file, "a", encoding="utf-8") as f:
                    f.write(f"{domain}\n")
                logger.info(f"已将域名加入黑名单: {domain}")
        except Exception as e:
            logger.warning(f"保存黑名单失败: {e}")

    def _visit_homepage(self) -> bool:
        """
        访问首页获取 browser token
        
        Returns:
            是否成功获取 token
        """
        try:
            api_base = self.config["base_url"].rstrip("/")
            
            # 访问首页
            res = self.session.get(
                f"{api_base}/",
                timeout=self.config["timeout"],
                impersonate=self.impersonate
            )
            
            if res.status_code != 200:
                logger.warning(f"访问首页失败: {res.status_code}")
                return False
            
            html_text = res.text
            
            # 提取 window.__BROWSER_AUTH.token
            match = re.search(r'window\.__BROWSER_AUTH\s*=\s*(\{[^}]+\})', html_text)
            if match:
                try:
                    auth_json = json.loads(match.group(1))
                    self._browser_token = auth_json.get("token")
                    if self._browser_token:
                        logger.debug("成功获取 browser token")
                        return True
                except json.JSONDecodeError:
                    pass
            
            logger.warning("未能从首页提取 browser token")
            return False
            
        except Exception as e:
            logger.error(f"访问首页异常: {e}")
            return False

    def create_email(self, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        创建新的临时邮箱

        Args:
            config: 配置参数（当前未使用）

        Returns:
            包含邮箱信息的字典:
            - email: 邮箱地址
            - service_id: 邮箱 token
            - token: 邮箱 token（同 service_id）
            - created_at: 创建时间戳
        """
        max_retries = self.config["max_retries"]
        base_delay = 2
        
        for attempt in range(max_retries):
            try:
                api_base = self.config["base_url"].rstrip("/")
                
                # 第一步：访问首页获取 browser token
                if not self._visit_homepage():
                    raise EmailServiceError("无法获取 browser token")
                
                # 第二步：生成邮箱
                headers = {
                    "Accept": "*/*",
                    "Content-Type": "application/json",
                    "sec-fetch-site": "same-origin",
                    "sec-fetch-mode": "cors",
                    "sec-fetch-dest": "empty",
                    "referer": f"{api_base}/",
                    "x-inbox-token": self._browser_token,
                }
                
                res = self.session.get(
                    f"{api_base}/api/generate-email",
                    headers=headers,
                    timeout=self.config["timeout"],
                    impersonate=self.impersonate
                )
                
                if res.status_code not in [200, 201]:
                    raise EmailServiceError(f"创建邮箱失败: {res.status_code} - {res.text[:200]}")
                
                data = res.json()
                if not data.get("success"):
                    error_msg = data.get('error', 'Unknown error')
                    raise EmailServiceError(f"创建邮箱失败: {error_msg}")
                
                email = data.get("data", {}).get("email")
                auth = data.get("auth", {})
                token = auth.get("token")
                
                if not email or not token:
                    raise EmailServiceError("未能从响应中获取邮箱地址或 token")
                
                # 检查域名是否在黑名单中
                email_domain = email.split("@")[1].lower() if "@" in email else ""
                if email_domain and email_domain in self._banned_domains:
                    logger.info(f"域名 {email_domain} 在黑名单中，重新生成...")
                    continue
                
                # 缓存邮箱信息
                email_info = {
                    "email": email,
                    "service_id": token,
                    "token": token,
                    "created_at": time.time(),
                    "browser_token": self._browser_token,
                }
                self._email_cache[email] = email_info
                
                logger.info(f"GPTMail 邮箱创建成功: {email}")
                self.update_status(True)
                return email_info
                
            except EmailServiceError as e:
                error_str = str(e).lower()
                
                # 不支持的域名错误
                if "unsupported" in error_str or "blocked" in error_str or "invalid domain" in error_str:
                    domain_match = re.search(r'@([a-zA-Z0-9.-]+)', str(e))
                    if domain_match:
                        blocked_domain = domain_match.group(1).lower()
                        self._save_banned_domain(blocked_domain)
                        logger.info(f"域名 {blocked_domain} 不支持，已加入黑名单")
                    continue
                
                # 网络错误 - 重试
                if "tls" in error_str or "ssl" in error_str or "timeout" in error_str or "connection" in error_str:
                    if attempt < max_retries - 1:
                        delay = base_delay * (2 ** attempt)
                        delay = min(delay, 30)
                        logger.warning(f"网络错误，{delay}秒后重试 ({attempt+1}/{max_retries}): {e}")
                        time.sleep(delay)
                        continue
                
                # 其他错误
                if attempt < max_retries - 1:
                    delay = base_delay * (attempt + 1)
                    logger.warning(f"创建失败，{delay}秒后重试 ({attempt+1}/{max_retries}): {e}")
                    time.sleep(delay)
                    continue
                
                self.update_status(False, e)
                raise
            
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = base_delay * (attempt + 1)
                    logger.warning(f"创建异常，{delay}秒后重试 ({attempt+1}/{max_retries}): {e}")
                    time.sleep(delay)
                    continue
                
                self.update_status(False, e)
                raise EmailServiceError(f"创建 GPTMail 邮箱失败: {e}")
        
        raise EmailServiceError(f"创建 GPTMail 邮箱失败: 超过最大重试次数 {max_retries}")

    def _fetch_emails(self, email: str, token: str) -> List[Dict[str, Any]]:
        """
        从 GPTMail 获取邮件列表

        Args:
            email: 邮箱地址
            token: 邮箱 token（创建邮箱时返回的 auth.token）

        Returns:
            邮件列表
        """
        try:
            api_base = self.config["base_url"].rstrip("/")
            
            # 直接使用 token（mail_token）作为 X-Inbox-Token
            # 这是原始代码的正确逻辑
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Inbox-Token": token,  # 关键：直接使用 mail_token
            }
            
            res = self.session.get(
                f"{api_base}/api/emails",
                params={"email": email},
                headers=headers,
                timeout=self.config["timeout"],
                impersonate="chrome131"  # 固定使用 chrome131
            )
            
            if res.status_code == 200:
                data = res.json()
                if data.get("success"):
                    emails = data.get("data", {}).get("emails", [])
                    return emails
            
            return []
            
        except Exception as e:
            logger.debug(f"获取邮件列表失败: {e}")
            return []

    def _fetch_email_detail(self, email_id: str, token: str) -> Optional[Dict[str, Any]]:
        """
        获取单封邮件详情

        Args:
            email_id: 邮件 ID
            token: 邮箱 token

        Returns:
            邮件详情字典
        """
        try:
            api_base = self.config["base_url"].rstrip("/")
            
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Inbox-Token": token,
            }
            
            res = self.session.get(
                f"{api_base}/api/email/{email_id}",
                headers=headers,
                timeout=self.config["timeout"],
                impersonate="chrome131"
            )
            
            if res.status_code == 200:
                data = res.json()
                if data.get("success"):
                    return data.get("data", {})
            
            return None
            
        except Exception as e:
            logger.debug(f"获取邮件详情失败: {e}")
            return None

    def _extract_verification_code(self, content: str) -> Optional[str]:
        """
        从邮件内容提取 6 位验证码

        Args:
            content: 邮件内容

        Returns:
            验证码或 None
        """
        if not content:
            return None
        
        patterns = [
            r"Verification code:?\s*(\d{6})",
            r"code is\s*(\d{6})",
            r"代码为[:：]?\s*(\d{6})",
            r"验证码[:：]?\s*(\d{6})",
            r">\s*(\d{6})\s*<",
            r"(?<![#&])\b(\d{6})\b",
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for code in matches:
                if code == "177010":  # 已知误判
                    continue
                return code
        
        return None

    def get_verification_code(
        self,
        email: str,
        email_id: str = None,
        timeout: int = 120,
        pattern: str = OTP_CODE_PATTERN,
        otp_sent_at: Optional[float] = None,
    ) -> Optional[str]:
        """
        从 GPTMail 获取验证码

        Args:
            email: 邮箱地址
            email_id: 邮箱 token（如果不提供，从缓存中查找）
            timeout: 超时时间（秒）
            pattern: 验证码正则表达式
            otp_sent_at: OTP 发送时间戳（暂未使用）

        Returns:
            验证码字符串，如果超时或未找到返回 None
        """
        token = email_id
        if not token:
            if email in self._email_cache:
                token = self._email_cache[email].get("token")
            else:
                logger.warning(f"未找到邮箱 {email} 的 token")
                return None
        
        if not token:
            logger.warning(f"邮箱 {email} 没有 token")
            return None
        
        logger.info(f"等待 GPTMail 验证码: {email}")
        
        start_time = time.time()
        seen_ids = set()
        poll_interval = self.config.get("poll_interval", 3.0)
        
        while time.time() - start_time < timeout:
            try:
                messages = self._fetch_emails(email, token)
                
                for msg in messages:
                    if not isinstance(msg, dict):
                        continue
                    
                    # 使用 id 作为唯一标识
                    msg_id = msg.get("id")
                    if not msg_id or msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)
                    
                    # 检查发件人
                    from_addr = msg.get("from_address", "")
                    if "openai.com" not in from_addr.lower():
                        continue
                    
                    # 获取邮件详情（关键：原始代码会单独获取详情）
                    detail = self._fetch_email_detail(msg_id, token)
                    if detail:
                        # 从详情中的 content 或 html_content 提取验证码
                        content = detail.get("content") or detail.get("html_content") or ""
                        if content:
                            code = self._extract_verification_code(content)
                            if code:
                                logger.info(f"GPTMail 验证码: {code}")
                                self.update_status(True)
                                return code
                
            except Exception as e:
                logger.debug(f"检查邮件时出错: {e}")
            
            time.sleep(poll_interval)
        
        logger.warning(f"GPTMail 等待验证码超时: {email}")
        return None

    def list_emails(self, **kwargs) -> List[Dict[str, Any]]:
        """
        列出所有缓存的邮箱

        Returns:
            邮箱列表
        """
        return list(self._email_cache.values())

    def delete_email(self, email_id: str) -> bool:
        """
        删除邮箱（从缓存中移除）

        Args:
            email_id: 邮箱 token

        Returns:
            是否删除成功
        """
        emails_to_delete = []
        for email, info in self._email_cache.items():
            if info.get("token") == email_id:
                emails_to_delete.append(email)
        
        for email in emails_to_delete:
            del self._email_cache[email]
            logger.info(f"从缓存中移除邮箱: {email}")
        
        return len(emails_to_delete) > 0

    def check_health(self) -> bool:
        """检查 GPTMail 服务是否可用"""
        try:
            api_base = self.config["base_url"].rstrip("/")
            
            res = self.session.get(
                f"{api_base}/",
                timeout=10,
                impersonate=self.impersonate
            )
            
            # 只要能访问首页就认为服务可用
            if res.status_code == 200:
                self.update_status(True)
                return True
            
            self.update_status(False, Exception(f"状态码: {res.status_code}"))
            return False
            
        except Exception as e:
            logger.warning(f"GPTMail 健康检查失败: {e}")
            self.update_status(False, e)
            return False

    def get_email_messages(self, email_id: str, **kwargs) -> List[Dict[str, Any]]:
        """
        获取邮箱中的邮件列表

        Args:
            email_id: 邮箱地址

        Returns:
            邮件列表
        """
        email_info = self._email_cache.get(email_id)
        if not email_info:
            return []
        
        return self._fetch_emails(email_info["email"], email_info["token"])

    def add_banned_domain(self, domain: str) -> None:
        """
        手动添加域名到黑名单

        Args:
            domain: 域名
        """
        self._save_banned_domain(domain)

    def get_banned_domains(self) -> set:
        """
        获取当前黑名单域名集合

        Returns:
            黑名单域名集合
        """
        return self._banned_domains.copy()
