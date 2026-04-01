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
import ipaddress
import json
import re
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
        attempt = 2
        while fake_value in self.reverse[category]:
            fake_value = self._make_unique_value(category, fake_value, attempt)
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Anonymize Kerio raw syslog TXT file")
    parser.add_argument("--input", required=True, help="Path to the source TXT file")
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    mapping_path = Path(args.mapping)

    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    mapping = MappingStore(mapping_path)
    anonymizer = KerioAnonymizer(mapping=mapping, seed=args.seed)

    input_text, detected_encoding = read_text_with_fallback(input_path, args.input_encoding)
    output_text = anonymizer.anonymize_text(input_text)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(output_text, encoding=args.output_encoding)
    mapping.save()

    print("Done.")
    print(f"Input            : {input_path}")
    print(f"Detected encoding: {detected_encoding}")
    print(f"Output           : {output_path}")
    print(f"Mapping          : {mapping_path}")


if __name__ == "__main__":
    main()
