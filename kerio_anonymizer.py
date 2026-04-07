#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Kerio raw syslog anonymizer.

What it does:
- reads a TXT file with raw Kerio syslog
- replaces sensitive values with fake generated ones
- persists a real -> fake mapping dictionary in JSON

Supported entities:
- email addresses
- IPv4 addresses
- usernames / logins
- subjects
- full names / display names
- standalone domain names
"""

from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable

try:
    from faker import Faker
except ImportError as exc:
    raise SystemExit("Package 'Faker' is required. Install it with: pip install Faker") from exc


CYRILLIC_RE = re.compile(r"[А-Яа-яЁё]")


class MappingStore:
    CATEGORIES = (
        "emails",
        "ips",
        "usernames",
        "subjects",
        "full_names",
        "domains",
        "other",
    )

    def __init__(self, path: Path):
        self.path = path
        self.data = {category: {} for category in self.CATEGORIES}
        self.reverse = {category: {} for category in self.CATEGORIES}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return

        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Mapping file is not valid JSON: {self.path}") from exc

        for category in self.CATEGORIES:
            category_data = loaded.get(category, {})
            if isinstance(category_data, dict):
                self.data[category] = self._normalize_category_mapping(category, category_data)

        self._build_reverse()

    def _build_reverse(self) -> None:
        for category, mapping in self.data.items():
            self.reverse[category] = {fake_value: hashed_key for hashed_key, fake_value in mapping.items()}

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def get_or_create(self, category: str, real_value: str, generator: Callable[[], str]) -> str:
        real_key = self._real_key(category, real_value)
        if real_key in self.data[category]:
            return self.data[category][real_key]

        fake_value = generator()
        base_fake_value = fake_value
        attempt = 2
        while fake_value in self.reverse[category]:
            fake_value = self._make_unique_value(category, base_fake_value, attempt)
            attempt += 1

        self.data[category][real_key] = fake_value
        self.reverse[category][fake_value] = real_key
        return fake_value

    @classmethod
    def _normalize_category_mapping(cls, category: str, mapping: dict[str, str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for key, fake_value in mapping.items():
            normalized_key = key if cls._looks_hashed(key) else cls._real_key(category, key)
            normalized[normalized_key] = fake_value
        return normalized

    @staticmethod
    def _looks_hashed(value: str) -> bool:
        return value.startswith("sha256:") and len(value) == 71

    @staticmethod
    def _real_key(category: str, real_value: str) -> str:
        digest = hashlib.sha256(f"{category}:{real_value}".encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    @staticmethod
    def _make_unique_value(category: str, fake_value: str, attempt: int) -> str:
        if category == "emails" and "@" in fake_value:
            local_part, _, domain = fake_value.partition("@")
            return f"{local_part}+{attempt}@{domain}"

        if category == "domains":
            marker = ".example.invalid"
            if fake_value.endswith(marker):
                prefix = fake_value[: -len(marker)]
                return f"{prefix}-{attempt}{marker}"
            return f"{fake_value}-{attempt}"

        if category == "ips":
            try:
                octets = fake_value.split(".")
                last_octet = int(octets[-1])
                octets[-1] = str(((last_octet - 1 + attempt) % 254) + 1)
                return ".".join(octets)
            except (ValueError, IndexError):
                return fake_value

        if category == "usernames":
            return f"{fake_value}_{attempt}"

        return f"{fake_value} {attempt}"


class KerioAnonymizer:
    EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b")
    IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
    DOMAIN_RE = re.compile(
        r"\b(?<!@)(?:[a-zA-Z0-9\-]+\.)+(?:local|lan|corp|ru|com|net|org|biz|info|io|internal)\b",
        re.IGNORECASE,
    )

    USER_PATTERNS = [
        re.compile(r'(\buser(?:name)?\s*[=:]\s*)([^\s,;"]+)', re.IGNORECASE),
        re.compile(r'(\blogin\s*[=:]\s*)([^\s,;"]+)', re.IGNORECASE),
        re.compile(r'(\baccount\s*[=:]\s*)([^\s,;"]+)', re.IGNORECASE),
        re.compile(r'(\bauthuser\s*[=:]\s*)([^\s,;"]+)', re.IGNORECASE),
        re.compile(r'(\bsasl_username\s*[=:]\s*)([^\s,;"]+)', re.IGNORECASE),
        re.compile(r'(\bowner\s*[=:]\s*)([^\s,;"]+)', re.IGNORECASE),
        re.compile(r'(\bmailbox\s*[=:]\s*)([^\s,;"]+)', re.IGNORECASE),
        re.compile(r'(\bfrom user\s+)([^\s,;"]+)', re.IGNORECASE),
        re.compile(r'(\bfor user\s+)([^\s,;"]+)', re.IGNORECASE),
    ]

    SUBJECT_PATTERNS = [
        re.compile(r'(\bsubject\s*[=:]\s*)("[^"]*"|\'[^\']*\'|[^\r\n]+)', re.IGNORECASE),
    ]

    FULLNAME_PATTERNS = [
        re.compile(r'(\bfromName\s*[=:]\s*)("[^"]+"|\'[^\']+\'|[^,;\r\n]+)', re.IGNORECASE),
        re.compile(r'(\bdisplayName\s*[=:]\s*)("[^"]+"|\'[^\']+\'|[^,;\r\n]+)', re.IGNORECASE),
        re.compile(r'(\bfullName\s*[=:]\s*)("[^"]+"|\'[^\']+\'|[^,;\r\n]+)', re.IGNORECASE),
        re.compile(r'(\bpersonalName\s*[=:]\s*)("[^"]+"|\'[^\']+\'|[^,;\r\n]+)', re.IGNORECASE),
        re.compile(r'(\bcn\s*[=:]\s*)("[^"]+"|\'[^\']+\'|[^,;\r\n]+)', re.IGNORECASE),
        re.compile(
            r'(\bname\s*[=:]\s*)("[^"]+"|\'[^\']+\'|[A-ZА-ЯЁ][^,;\r\n]{2,}\s+[A-ZА-ЯЁ][^,;\r\n]{1,})',
            re.IGNORECASE,
        ),
    ]

    def __init__(self, mapping: MappingStore, seed: int = 42):
        self.mapping = mapping
        self.seed = seed

    def anonymize_text(self, text: str) -> str:
        text = self._replace_emails(text)
        text = self._replace_ips(text)
        text = self._replace_subjects(text)
        text = self._replace_full_names(text)
        text = self._replace_usernames(text)
        text = self._replace_domains(text)
        return text

    def _replace_emails(self, text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            real_email = match.group(0)
            return self.mapping.get_or_create("emails", real_email, lambda: self._fake_email(real_email))

        return self.EMAIL_RE.sub(repl, text)

    def _replace_ips(self, text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            real_ip = match.group(0)
            if real_ip == "127.0.0.1":
                return real_ip
            return self.mapping.get_or_create("ips", real_ip, lambda: self._fake_ip(real_ip))

        return self.IPV4_RE.sub(repl, text)

    def _replace_subjects(self, text: str) -> str:
        for pattern in self.SUBJECT_PATTERNS:
            text = pattern.sub(self._subject_sub, text)
        return text

    def _replace_full_names(self, text: str) -> str:
        for pattern in self.FULLNAME_PATTERNS:
            text = pattern.sub(self._fullname_sub, text)
        return text

    def _replace_usernames(self, text: str) -> str:
        for pattern in self.USER_PATTERNS:
            text = pattern.sub(self._username_sub, text)
        return text

    def _replace_domains(self, text: str) -> str:
        def repl(match: re.Match[str]) -> str:
            real_domain = match.group(0)
            if real_domain.endswith(".example.invalid") or real_domain == "example.org":
                return real_domain
            return self.mapping.get_or_create("domains", real_domain, lambda: self._fake_domain(real_domain))

        return self.DOMAIN_RE.sub(repl, text)

    def _username_sub(self, match: re.Match[str]) -> str:
        prefix = match.group(1)
        real_username = match.group(2).strip()

        if not self._looks_like_username(real_username):
            return match.group(0)

        fake_username = self.mapping.get_or_create(
            "usernames",
            real_username,
            lambda: self._fake_username(real_username),
        )
        return f"{prefix}{fake_username}"

    def _subject_sub(self, match: re.Match[str]) -> str:
        prefix = match.group(1)
        real_subject = match.group(2).strip()
        core, quote_left, quote_right = self._unwrap_quoted(real_subject)

        if not core:
            return match.group(0)

        fake_subject = self.mapping.get_or_create(
            "subjects",
            core,
            lambda: self._fake_subject(core),
        )
        return f"{prefix}{quote_left}{fake_subject}{quote_right}"

    def _fullname_sub(self, match: re.Match[str]) -> str:
        prefix = match.group(1)
        real_name = match.group(2).strip()
        core, quote_left, quote_right = self._unwrap_quoted(real_name)

        if not self._looks_like_full_name(core):
            return match.group(0)

        fake_name = self.mapping.get_or_create(
            "full_names",
            core,
            lambda: self._fake_full_name(core),
        )
        return f"{prefix}{quote_left}{fake_name}{quote_right}"

    def _fake_email(self, real_email: str) -> str:
        local_part, _, domain = real_email.partition("@")
        fake_local = self.mapping.get_or_create(
            "usernames",
            local_part,
            lambda: self._fake_username(local_part),
        )
        fake_domain = self.mapping.get_or_create(
            "domains",
            domain,
            lambda: self._fake_domain(domain),
        )
        return f"{self._slug(fake_local)}@{fake_domain}"

    def _fake_ip(self, real_ip: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(real_ip)
        except ValueError:
            return "203.0.113.10"

        digest = hashlib.sha256(real_ip.encode("utf-8")).digest()

        if ip_obj.is_private:
            if real_ip.startswith("10."):
                return f"10.{digest[0]}.{digest[1]}.{max(1, digest[2])}"
            if real_ip.startswith("192.168."):
                return f"192.168.{digest[0]}.{max(1, digest[1])}"
            if real_ip.startswith("172."):
                second_octet = 16 + (digest[0] % 16)
                return f"172.{second_octet}.{digest[1]}.{max(1, digest[2])}"
            return f"10.{digest[0]}.{digest[1]}.{max(1, digest[2])}"

        blocks = [
            (192, 0, 2),
            (198, 51, 100),
            (203, 0, 113),
        ]
        octet_a, octet_b, octet_c = blocks[digest[0] % len(blocks)]
        octet_d = max(1, digest[1])
        return f"{octet_a}.{octet_b}.{octet_c}.{octet_d}"

    def _fake_username(self, real_username: str) -> str:
        fake_faker = self._make_faker(real_username, locale="ru_RU" if CYRILLIC_RE.search(real_username) else "en_US")

        separator = "."
        if "_" in real_username:
            separator = "_"
        elif "-" in real_username:
            separator = "-"

        first_name = fake_faker.first_name().lower()
        last_name = fake_faker.last_name().lower()
        candidate = f"{first_name}{separator}{last_name}"
        candidate = re.sub(r"[^a-zA-Zа-яА-ЯёЁ0-9._\-]", "", candidate)
        return candidate[:32] or "user.fake"

    def _fake_subject(self, real_subject: str) -> str:
        neutral_subjects = [
            "Service notification",
            "Scheduled maintenance",
            "User message",
            "System alert",
            "Mail delivery report",
            "Calendar update",
            "Security notification",
            "Access request",
            "Meeting information",
            "Automated message",
        ]
        digest = int(hashlib.sha256(real_subject.encode("utf-8")).hexdigest(), 16)
        return neutral_subjects[digest % len(neutral_subjects)]

    def _fake_full_name(self, real_name: str) -> str:
        locale = "ru_RU" if CYRILLIC_RE.search(real_name) else "en_US"
        fake_faker = self._make_faker(real_name, locale=locale)
        parts = [part for part in re.split(r"\s+", real_name.strip()) if part]
        part_count = len(parts)

        if locale == "ru_RU":
            if part_count >= 3:
                return f"{fake_faker.last_name()} {fake_faker.first_name()} {fake_faker.middle_name()}"
            if part_count == 2:
                return f"{fake_faker.first_name()} {fake_faker.last_name()}"
            return fake_faker.name()

        if part_count >= 3:
            return f"{fake_faker.first_name()} {fake_faker.last_name()} {fake_faker.last_name()}"
        if part_count == 2:
            return f"{fake_faker.first_name()} {fake_faker.last_name()}"
        return fake_faker.name()

    def _fake_domain(self, real_domain: str) -> str:
        digest = hashlib.sha256(real_domain.lower().encode("utf-8")).hexdigest()[:10]
        return f"domain-{digest}.example.invalid"

    def _make_faker(self, source: str, locale: str) -> Faker:
        fake_faker = Faker(locale)
        fake_faker.seed_instance(self._seed_for(source))
        return fake_faker

    def _seed_for(self, value: str) -> int:
        digest = hashlib.sha256(f"{self.seed}:{value}".encode("utf-8")).hexdigest()
        return int(digest[:16], 16)

    @staticmethod
    def _unwrap_quoted(value: str) -> tuple[str, str, str]:
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            return value[1:-1], value[0], value[-1]
        return value, "", ""

    @staticmethod
    def _looks_like_username(value: str) -> bool:
        if not value or len(value) < 2:
            return False
        if "@" in value:
            return False
        if re.fullmatch(r"[\d.]+", value):
            return False
        return True

    @staticmethod
    def _looks_like_full_name(value: str) -> bool:
        if not value or len(value) < 3:
            return False
        if "@" in value or "." in value or "\\" in value or "/" in value:
            return False
        if re.fullmatch(r"[\d\s\-]+", value):
            return False
        return True

    @staticmethod
    def _slug(value: str) -> str:
        value = value.lower()
        value = re.sub(r"\s+", ".", value)
        value = re.sub(r"[^a-zA-Z0-9._\-]", "", value)
        return value.strip(".") or "user"


def read_text_with_fallback(path: Path, preferred_encoding: str) -> tuple[str, str]:
    tried = []
    encodings = [preferred_encoding, "utf-8-sig", "cp1251", "cp866"]

    for encoding in encodings:
        if encoding in tried:
            continue
        tried.append(encoding)
        try:
            return path.read_text(encoding=encoding), encoding
        except UnicodeDecodeError:
            continue

    return path.read_text(encoding=preferred_encoding, errors="replace"), f"{preferred_encoding} (with replacement)"


def decode_bytes_with_fallback(data: bytes, preferred_encoding: str) -> tuple[str, str]:
    tried = []
    encodings = [preferred_encoding, "utf-8-sig", "cp1251", "cp866"]

    for encoding in encodings:
        if encoding in tried:
            continue
        tried.append(encoding)
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue

    return data.decode(preferred_encoding, errors="replace"), f"{preferred_encoding} (with replacement)"


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip().lstrip("\ufeff")
        value = value.strip()

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        values[key] = value

    return values


def env_or_arg(arg_value: str | None, env_values: dict[str, str], env_name: str, default: str | None = None) -> str | None:
    if arg_value:
        return arg_value
    return env_values.get(env_name) or default


def env_bool(env_values: dict[str, str], env_name: str, default: bool = False) -> bool:
    value = env_values.get(env_name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


class KerioApiClient:
    def __init__(self, api_url: str, user: str, password: str, verify_tls: bool = True):
        self.api_url = api_url
        self.user = user
        self.password = password
        self.token: str | None = None
        self.request_id = 1

        cookie_jar = http.cookiejar.CookieJar()
        handlers: list[urllib.request.BaseHandler] = [urllib.request.HTTPCookieProcessor(cookie_jar)]
        if not verify_tls:
            handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
        self.opener = urllib.request.build_opener(*handlers)

    def login(self) -> None:
        result = self.call(
            "Session.login",
            {
                "userName": self.user,
                "password": self.password,
                "application": {
                    "name": "kerio-syslog-anonymizer",
                    "vendor": "foksk76",
                    "version": "0.1",
                },
            },
            include_token=False,
        )
        token = result.get("token")
        if not token:
            raise SystemExit("Kerio API login did not return a session token.")
        self.token = token

    def call(self, method: str, params: dict[str, object], include_token: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params,
        }
        self.request_id += 1

        headers = {
            "Accept": "application/json-rpc",
            "Content-Type": "application/json-rpc; charset=UTF-8",
            "User-Agent": "kerio-syslog-anonymizer",
        }
        if include_token:
            if not self.token:
                raise SystemExit("Kerio API token is not available. Login must run first.")
            payload["token"] = self.token
            headers["X-Token"] = self.token

        request = urllib.request.Request(
            self.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with self.opener.open(request, timeout=60) as response:
                response_data = response.read()
        except urllib.error.URLError as exc:
            raise SystemExit(f"Kerio API request failed for {method}: {exc}") from exc

        try:
            decoded = json.loads(response_data.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Kerio API returned non-JSON response for {method}.") from exc

        if "error" in decoded:
            raise SystemExit(f"Kerio API error for {method}: {decoded['error']}")

        result = decoded.get("result", {})
        if not isinstance(result, dict):
            raise SystemExit(f"Kerio API returned unexpected result for {method}.")
        return result

    def export_log_plain_text(self, log_name: str, from_line: int, count_lines: int) -> bytes:
        result = self.call(
            "Logs.exportLogRelative",
            {
                "logName": log_name,
                "fromLine": from_line,
                "countLines": count_lines,
                "type": "PlainText",
            },
        )
        download = result.get("fileDownload")
        if not isinstance(download, dict) or not download.get("url"):
            raise SystemExit(f"Kerio API did not return a download URL for log '{log_name}'.")

        return self.download(str(download["url"]))

    def download(self, download_url: str) -> bytes:
        url = urllib.parse.urljoin(self.api_url, download_url)
        headers = {"User-Agent": "kerio-syslog-anonymizer"}
        if self.token:
            headers["X-Token"] = self.token

        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with self.opener.open(request, timeout=120) as response:
                return response.read()
        except urllib.error.URLError as exc:
            raise SystemExit(f"Kerio API log download failed: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Anonymize Kerio raw syslog TXT file")
    parser.add_argument("--input", help="Path to the source TXT file. Required unless --kerio-fetch-log is used")
    parser.add_argument("--output", required=True, help="Path to the anonymized TXT file")
    parser.add_argument("--mapping", required=True, help="Path to the real-fake mapping JSON file")
    parser.add_argument("--seed", type=int, default=42, help="Base seed for deterministic fake generation")
    parser.add_argument(
        "--input-encoding",
        default="utf-8",
        help="Preferred input encoding. Fallbacks: utf-8-sig, cp1251, cp866",
    )
    parser.add_argument(
        "--output-encoding",
        default="utf-8",
        help="Encoding for the anonymized output file",
    )
    parser.add_argument("--env-file", default=".env", help="Path to .env file with Kerio API settings")
    parser.add_argument("--kerio-fetch-log", action="store_true", help="Fetch source log from Kerio Connect API")
    parser.add_argument("--kerio-api-url", help="Kerio admin API JSON-RPC URL. Env: KERIO_API_URL")
    parser.add_argument("--kerio-api-user", help="Kerio API username. Env: KERIO_API_USER")
    parser.add_argument("--kerio-api-password", help="Kerio API password. Env: KERIO_API_PASSWORD")
    parser.add_argument("--kerio-log-name", help="Kerio log name to export. Env: KERIO_LOG_NAME")
    parser.add_argument("--kerio-from-line", type=int, help="First Kerio log line to export. Env: KERIO_LOG_FROM_LINE")
    parser.add_argument("--kerio-count-lines", type=int, help="Number of Kerio log lines to export. Env: KERIO_LOG_COUNT_LINES")
    parser.add_argument("--kerio-insecure", action="store_true", help="Disable TLS certificate verification for lab Kerio servers. Env: KERIO_API_INSECURE=true")
    parser.add_argument("--kerio-save-raw", help="Optional path to save the raw log downloaded from Kerio API. Env: KERIO_SAVE_RAW")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    env_values = load_env_file(Path(args.env_file))

    output_path = Path(args.output)
    mapping_path = Path(args.mapping)

    mapping = MappingStore(mapping_path)
    anonymizer = KerioAnonymizer(mapping=mapping, seed=args.seed)

    if args.kerio_fetch_log:
        api_url = env_or_arg(args.kerio_api_url, env_values, "KERIO_API_URL")
        api_user = env_or_arg(args.kerio_api_user, env_values, "KERIO_API_USER")
        api_password = env_or_arg(args.kerio_api_password, env_values, "KERIO_API_PASSWORD")
        log_name = env_or_arg(args.kerio_log_name, env_values, "KERIO_LOG_NAME", "mail")
        save_raw = env_or_arg(args.kerio_save_raw, env_values, "KERIO_SAVE_RAW")
        from_line = args.kerio_from_line if args.kerio_from_line is not None else int(env_values.get("KERIO_LOG_FROM_LINE", "0"))
        count_lines = args.kerio_count_lines if args.kerio_count_lines is not None else int(env_values.get("KERIO_LOG_COUNT_LINES", "50000"))
        insecure = args.kerio_insecure or env_bool(env_values, "KERIO_API_INSECURE", False)

        missing = [
            name
            for name, value in {
                "KERIO_API_URL": api_url,
                "KERIO_API_USER": api_user,
                "KERIO_API_PASSWORD": api_password,
            }.items()
            if not value
        ]
        if missing:
            raise SystemExit(f"Missing Kerio API settings: {', '.join(missing)}. See .env.example.")

        client = KerioApiClient(
            api_url=str(api_url),
            user=str(api_user),
            password=str(api_password),
            verify_tls=not insecure,
        )
        client.login()
        raw_bytes = client.export_log_plain_text(str(log_name), from_line, count_lines)
        input_text, detected_encoding = decode_bytes_with_fallback(raw_bytes, args.input_encoding)
        input_label = f"Kerio API log '{log_name}'"

        if save_raw:
            save_raw_path = Path(save_raw)
            save_raw_path.parent.mkdir(parents=True, exist_ok=True)
            save_raw_path.write_text(input_text, encoding=args.output_encoding)
    else:
        if not args.input:
            raise SystemExit("--input is required unless --kerio-fetch-log is used.")

        input_path = Path(args.input)
        if not input_path.exists():
            raise SystemExit(f"Input file not found: {input_path}")

        input_text, detected_encoding = read_text_with_fallback(input_path, args.input_encoding)
        input_label = str(input_path)

    output_text = anonymizer.anonymize_text(input_text)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output_text, encoding=args.output_encoding)
    mapping.save()

    print("Done.")
    print(f"Input            : {input_label}")
    print(f"Detected encoding: {detected_encoding}")
    print(f"Output           : {output_path}")
    print(f"Mapping          : {mapping_path}")


if __name__ == "__main__":
    main()
