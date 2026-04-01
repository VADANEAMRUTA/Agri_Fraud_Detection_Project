"""Train a hybrid fraud detector with URL intelligence and contextual NLP."""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    import tldextract
except Exception:  # pragma: no cover
    tldextract = None

try:
    import whois
except Exception:  # pragma: no cover
    whois = None

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover
    XGBClassifier = None


RANDOM_SEED = 42
MODELS_DIR = Path("models")
MODEL_PATH = MODELS_DIR / "fraud_detector_v2.pkl"
VECTORIZER_PATH = MODELS_DIR / "vectorizer_v2.pkl"
METRICS_PATH = MODELS_DIR / "training_metrics_v2.json"
CACHE_PATH = MODELS_DIR / "domain_reputation_cache.json"

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "work", "shop", "live", "buzz", "gq", "fit", "rest", "zip", "country"
}
SENSITIVE_KEYWORDS = {
    "government", "gov", "subsidy", "bank", "banking", "loan", "kyc", "aadhaar", "pan", "upi",
    "farmer", "scheme", "verify", "verification", "account", "insurance", "pension",
    "सरकार", "किसान", "योजना", "बैंक", "सब्सिडी", "खाता", "लोन", "सत्यापन", "केवाईसी",
}
URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\blast chance\b", r"\bfinal notice\b", r"\bact now\b",
    r"\bverify now\b", r"\baccount blocked\b", r"\bwithin \d+ hours\b",
    r"तुरंत", r"अभी", r"अंतिम", r"अभी करें", r"फौरन", r"जल्दी",
]
THREAT_PATTERNS = [
    r"\bblocked\b", r"\bsuspend(?:ed)?\b", r"\blocked\b", r"\bpenalty\b", r"\bfreeze(?:d)?\b",
    r"\bdisabled\b", r"\bexpire(?:d|s)?\b", r"\bdeactivated\b",
    r"बंद", r"निलंबित", r"जुर्माना", r"फ्रीज", r"समाप्त",
]
OFFER_PATTERNS = [
    r"\bwinner\b", r"\blottery\b", r"\bbonus\b", r"\bfree\b", r"\bprize\b", r"\bcashback\b",
    r"\bexclusive offer\b", r"\bguaranteed\b", r"\bprocessing fee\b",
    r"इनाम", r"लॉटरी", r"मुफ्त", r"बोनस", r"फ्री", r"ऑफर", r"गारंटी",
]

PROTECTED_DOMAINS: Dict[str, str] = {
    "farmer.gov.in": "government",
    "pmkisan.gov.in": "government",
    "india.gov.in": "government",
    "nic.in": "government",
    "sbi.co.in": "banking",
    "onlinesbi.sbi": "banking",
}

DOMAIN_AGE_PRIORS = {
    "farmer.gov.in": 3650,
    "pmkisan.gov.in": 1800,
    "india.gov.in": 7000,
    "nic.in": 9000,
    "sbi.co.in": 7000,
    "onlinesbi.sbi": 2500,
}

HOMOGLYPH_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})


def extract_first_url(text: str) -> Optional[str]:
    match = re.search(r"https?://\S+|www\.\S+", text or "", flags=re.IGNORECASE)
    return match.group(0) if match else None


def ensure_scheme(url: str) -> str:
    if not url:
        return ""
    return url if re.match(r"^[a-z][a-z0-9+\-.]*://", url, flags=re.IGNORECASE) else f"https://{url}"


def normalize_host(host: str) -> str:
    value = (host or "").strip().lower().rstrip(".")
    if not value:
        return ""
    try:
        return value.encode("idna").decode("ascii")
    except Exception:
        return value


def split_domain(url: str) -> Dict[str, str]:
    parsed = urlparse(ensure_scheme(url))
    host = normalize_host(parsed.netloc or parsed.path.split("/")[0])
    if not host:
        return {"host": "", "subdomain": "", "domain": "", "suffix": "", "registered_domain": "", "path": ""}

    if tldextract is not None:
        extracted = tldextract.extract(host)
        registered = ".".join([part for part in [extracted.domain, extracted.suffix] if part])
        return {
            "host": host,
            "subdomain": extracted.subdomain or "",
            "domain": extracted.domain or "",
            "suffix": extracted.suffix or "",
            "registered_domain": registered,
            "path": parsed.path or "",
        }

    pieces = host.split(".")
    compound_suffixes = {"gov.in", "co.in", "org.in", "ac.in", "net.in"}
    if len(pieces) >= 3 and ".".join(pieces[-2:]) in compound_suffixes:
        suffix = ".".join(pieces[-2:])
        domain = pieces[-3]
        subdomain = ".".join(pieces[:-3]) if len(pieces) > 3 else ""
    else:
        suffix = pieces[-1] if len(pieces) >= 2 else ""
        domain = pieces[-2] if len(pieces) >= 2 else pieces[0]
        subdomain = ".".join(pieces[:-2]) if len(pieces) > 2 else ""
    return {
        "host": host,
        "subdomain": subdomain,
        "domain": domain,
        "suffix": suffix,
        "registered_domain": ".".join([part for part in [domain, suffix] if part]),
        "path": parsed.path or "",
    }


def alnum_tokens(text: str) -> List[str]:
    return re.findall(r"[a-z0-9\u0900-\u097f]+", (text or "").lower())


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insertions = previous[j] + 1
            deletions = current[j - 1] + 1
            substitutions = previous[j - 1] + (left_char != right_char)
            current.append(min(insertions, deletions, substitutions))
        previous = current
    return previous[-1]


def normalize_homoglyphs(label: str) -> str:
    return (label or "").translate(HOMOGLYPH_TRANSLATION)


def build_typosquat_domain(domain: str, strategy: str) -> str:
    details = split_domain(domain)
    label = details["domain"]
    suffix = details["suffix"]
    if not label:
        return domain

    if strategy == "homoglyph":
        replacements = {"o": "0", "i": "1", "e": "3", "a": "4"}
        updated = "".join(replacements.get(char, char) for char in label)
    elif strategy == "swap" and len(label) > 3:
        updated = label[:1] + label[2] + label[1] + label[3:]
    elif strategy == "drop" and len(label) > 4:
        updated = label[:-1]
    elif strategy == "tld":
        return f"{label}.xyz"
    elif domain == "farmer.gov.in":
        updated = "former"
    elif domain == "pmkisan.gov.in":
        updated = "pmkissan"
    elif domain == "sbi.co.in":
        updated = "sbl"
    else:
        updated = label[:-1] + ("x" if label[-1] != "x" else "z")

    return f"{updated}.{suffix}" if suffix else updated


class DomainReputationCache:
    def __init__(self, cache_path: Path = CACHE_PATH):
        self.cache_path = cache_path
        self._cache = self._load()

    def _load(self) -> Dict[str, Dict[str, object]]:
        if self.cache_path.exists():
            try:
                with self.cache_path.open("r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                if isinstance(payload, dict):
                    return payload
            except Exception:
                pass
        return {}

    def save(self) -> None:
        self.cache_path.parent.mkdir(exist_ok=True)
        with self.cache_path.open("w", encoding="utf-8") as handle:
            json.dump(self._cache, handle, indent=2, ensure_ascii=False)

    def get_age_days(self, registered_domain: str, allow_live_lookup: bool = False) -> Optional[int]:
        domain = normalize_host(registered_domain)
        if not domain:
            return None

        cached = self._cache.get(domain)
        if cached and isinstance(cached.get("age_days"), (int, float)):
            return int(cached["age_days"])

        if domain in DOMAIN_AGE_PRIORS:
            age = int(DOMAIN_AGE_PRIORS[domain])
            self._cache[domain] = {"age_days": age, "source": "local_prior"}
            return age

        if allow_live_lookup:
            age = self._lookup_live(domain)
            if age is not None:
                self._cache[domain] = {"age_days": int(age), "source": "live_lookup"}
                return int(age)
        return None

    def _lookup_live(self, domain: str) -> Optional[int]:
        now = datetime.now(timezone.utc)

        if whois is not None:
            try:
                info = whois.whois(domain)
                created = getattr(info, "creation_date", None)
                if isinstance(created, list):
                    created = next((item for item in created if item), None)
                if isinstance(created, datetime):
                    if created.tzinfo is None:
                        created = created.replace(tzinfo=timezone.utc)
                    return max((now - created).days, 0)
            except Exception:
                pass

        if requests is not None:
            try:
                response = requests.get(
                    f"https://rdap.org/domain/{domain}",
                    timeout=5,
                    headers={"Accept": "application/json"},
                )
                if response.ok:
                    payload = response.json()
                    for event in payload.get("events", []):
                        if event.get("eventAction") == "registration":
                            created = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                            return max((now - created).days, 0)
            except Exception:
                pass
        return None


class DomainFeatureExtractor:
    def __init__(
        self,
        protected_domains: Optional[Dict[str, str]] = None,
        suspicious_tlds: Optional[Iterable[str]] = None,
        cache: Optional[DomainReputationCache] = None,
        allow_live_lookup: bool = False,
    ):
        self.protected_domains = dict(protected_domains or PROTECTED_DOMAINS)
        self.suspicious_tlds = set(suspicious_tlds or SUSPICIOUS_TLDS)
        self.cache = cache or DomainReputationCache()
        self.allow_live_lookup = allow_live_lookup
        self.feature_names = [
            "url_present",
            "https_scheme",
            "host_length",
            "domain_length",
            "subdomain_depth",
            "hyphen_count",
            "digit_count",
            "path_depth",
            "query_param_count",
            "ip_literal_host",
            "suspicious_tld",
            "gov_sensitive_tld_mismatch",
            "punycode_flag",
            "homoglyph_flag",
            "min_edit_distance",
            "typosquat_flag",
            "typosquat_similarity_score",
            "protected_domain_exact",
            "protected_context_mismatch",
            "new_domain_flag",
            "domain_age_days_log",
            "banking_context_flag",
            "government_context_flag",
            "offer_context_flag",
            "urgency_context_flag",
            "threat_context_flag",
            "text_domain_similarity_hint",
        ]

    def transform(self, records: Sequence[Dict[str, str]]) -> np.ndarray:
        return np.array([self.extract_record_features(record)[0] for record in records], dtype=float)

    def detect_typosquatting(self, registered_domain: str) -> Tuple[float, str, float]:
        candidate = split_domain(registered_domain).get("registered_domain", "") or normalize_host(registered_domain)
        if not candidate or candidate in self.protected_domains:
            return 0.0, "", 0.0

        best_target = ""
        best_score = 0.0
        for protected_domain in self.protected_domains:
            similarity = SequenceMatcher(None, candidate, protected_domain).ratio()
            if similarity > best_score:
                best_score = similarity
                best_target = protected_domain

        if best_target and best_score > 0.85:
            return 1.0, best_target, float(best_score)
        return 0.0, "", float(best_score)

    def explain(self, record: Dict[str, str], top_n: int = 8) -> List[Dict[str, float]]:
        values, notes, metadata = self.extract_record_features(record)
        priority = {
            "typosquat_flag": 9.0,
            "suspicious_tld": 9.0,
            "gov_sensitive_tld_mismatch": 8.0,
            "homoglyph_flag": 9.0,
            "typosquat_similarity_score": 7.0,
            "protected_context_mismatch": 8.0,
            "new_domain_flag": 8.0,
            "offer_context_flag": 6.0,
            "urgency_context_flag": 6.0,
            "threat_context_flag": 6.0,
            "protected_domain_exact": 5.0,
            "domain_age_days_log": 4.0,
        }
        items = [{"feature": f"signal::{note}", "importance": 10.0} for note in notes[:top_n]]
        if metadata.get("typosquat_target"):
            items.insert(
                0,
                {
                    "feature": f"alert::Typosquatting detected: {metadata['registered_domain']} is trying to mimic {metadata['typosquat_target']}",
                    "importance": 12.0,
                },
            )
        for name, value in zip(self.feature_names, values):
            if name not in priority or abs(float(value)) <= 0:
                continue
            items.append({"feature": f"domain::{name}", "importance": float(value) * priority[name]})
        items.sort(key=lambda item: abs(item["importance"]), reverse=True)
        return items[:top_n]

    def extract_record_features(self, record: Dict[str, str]) -> Tuple[List[float], List[str], Dict[str, object]]:
        text = record.get("text", "") or ""
        url = record.get("url", "") or ""
        details = split_domain(url) if url else {"host": "", "domain": "", "suffix": "", "registered_domain": "", "subdomain": "", "path": ""}
        host = details["host"]
        registered_domain = details["registered_domain"]
        domain_label = details["domain"]
        suffix = details["suffix"]
        parsed = urlparse(ensure_scheme(url)) if url else urlparse("")
        lower_text = text.lower()
        tokens = set(alnum_tokens(lower_text))

        protected_exact = 1.0 if registered_domain in self.protected_domains else 0.0
        age_days = self.cache.get_age_days(registered_domain, allow_live_lookup=self.allow_live_lookup) if registered_domain else None
        new_domain_flag = 1.0 if age_days is not None and age_days < 180 else 0.0

        suspicious_tld = 1.0 if suffix.split(".")[-1] in self.suspicious_tlds else 0.0
        sensitive_context = 1.0 if any(keyword in lower_text for keyword in SENSITIVE_KEYWORDS) else 0.0
        gov_context = 1.0 if any(keyword in lower_text for keyword in {"gov", "government", "scheme", "subsidy", "farmer", "सरकार", "किसान", "योजना"}) else 0.0
        bank_context = 1.0 if any(keyword in lower_text for keyword in {"bank", "kyc", "loan", "upi", "account", "बैंक", "लोन", "खाता", "केवाईसी"}) else 0.0
        offer_context = 1.0 if any(re.search(pattern, lower_text) for pattern in OFFER_PATTERNS) else 0.0
        urgency_context = 1.0 if any(re.search(pattern, lower_text) for pattern in URGENCY_PATTERNS) else 0.0
        threat_context = 1.0 if any(re.search(pattern, lower_text) for pattern in THREAT_PATTERNS) else 0.0

        homoglyph_flag = 0.0
        min_edit_distance = 99
        protected_context_mismatch = 0.0
        typosquat_flag = 0.0
        typosquat_similarity_score = 0.0
        similarity_hint = 0.0
        notes: List[str] = []
        normalized_label = normalize_homoglyphs(domain_label)
        typosquat_flag, typosquat_target, typosquat_similarity_score = self.detect_typosquatting(registered_domain)
        if typosquat_flag:
            notes.append(
                f"Typosquatting detected: {registered_domain} is trying to mimic {typosquat_target}"
            )

        for protected_domain, category in self.protected_domains.items():
            protected_details = split_domain(protected_domain)
            protected_label = protected_details["domain"]
            protected_registered = protected_details["registered_domain"]

            if normalized_label == protected_label and registered_domain != protected_registered:
                homoglyph_flag = 1.0
                notes.append(f"homoglyph_like_{protected_registered}")

            distance = levenshtein_distance(domain_label, protected_label)
            min_edit_distance = min(min_edit_distance, distance)
            if 0 < distance <= 2 and registered_domain != protected_registered and not typosquat_flag:
                notes.append(f"typosquat_like_{protected_registered}")

            if protected_label in tokens:
                similarity_hint = 1.0

            if protected_exact and category == "government" and offer_context:
                protected_context_mismatch = 1.0
                notes.append("government_domain_with_offer_language")
            if protected_exact and category == "banking" and offer_context:
                protected_context_mismatch = 1.0
                notes.append("bank_domain_with_offer_language")

        if min_edit_distance == 99:
            min_edit_distance = 10

        gov_sensitive_tld_mismatch = 1.0 if suspicious_tld and sensitive_context else 0.0
        punycode_flag = 1.0 if "xn--" in host else 0.0
        ip_literal_host = 1.0 if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or "") is not None else 0.0

        if suspicious_tld:
            notes.append("suspicious_tld")
        if new_domain_flag:
            notes.append("newly_registered_domain")
        if gov_sensitive_tld_mismatch:
            notes.append("sensitive_context_on_cheap_tld")

        values = [
            1.0 if url else 0.0,
            1.0 if parsed.scheme == "https" else 0.0,
            float(len(host)),
            float(len(domain_label)),
            float(len([part for part in details.get("subdomain", "").split(".") if part])),
            float(host.count("-")),
            float(sum(char.isdigit() for char in host)),
            float(len([part for part in (parsed.path or "").split("/") if part])),
            float(len(re.findall(r"[?&][^=]+=([^&]+)", url))),
            ip_literal_host,
            suspicious_tld,
            gov_sensitive_tld_mismatch,
            punycode_flag,
            homoglyph_flag,
            float(min_edit_distance),
            typosquat_flag,
            typosquat_similarity_score,
            protected_exact,
            protected_context_mismatch,
            new_domain_flag,
            float(math.log1p(age_days if age_days is not None else 0)),
            bank_context,
            gov_context,
            offer_context,
            urgency_context,
            threat_context,
            similarity_hint,
        ]
        metadata = {
            "registered_domain": registered_domain,
            "typosquat_target": typosquat_target,
            "typosquat_flag": float(typosquat_flag),
            "typosquat_similarity_score": float(typosquat_similarity_score),
        }
        return values, notes, metadata


class FallbackEmbeddingProjector(BaseEstimator, TransformerMixin):
    """Deterministic lightweight fallback when sentence-transformers is unavailable."""

    def __init__(self, dimensions: int = 32):
        self.dimensions = dimensions

    def fit(self, texts: Sequence[str], y=None):
        return self

    def transform(self, texts: Sequence[str]) -> np.ndarray:
        output = np.zeros((len(texts), self.dimensions), dtype=float)
        for row_index, text in enumerate(texts):
            for token in alnum_tokens(text):
                output[row_index, hash(token) % self.dimensions] += 1.0
        norms = np.linalg.norm(output, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return output / norms


class SentenceEmbeddingExtractor(BaseEstimator, TransformerMixin):
    def __init__(self, model_name: str = "paraphrase-multilingual-MiniLM-L12-v2", dimensions: int = 32):
        self.model_name = model_name
        self.dimensions = dimensions
        self.available = False
        self.backend = None
        self.model = None
        self.fallback = FallbackEmbeddingProjector(dimensions=dimensions)

    def fit(self, texts: Sequence[str], y=None):
        self.fallback.fit(texts)
        allow_download = os.getenv("ALLOW_MODEL_DOWNLOAD", "0") == "1"
        try:
            from sentence_transformers import SentenceTransformer

            self.model = SentenceTransformer(self.model_name, local_files_only=not allow_download)
            self.backend = "sentence-transformers"
            self.available = True
        except Exception:
            self.model = None
            self.backend = "fallback"
            self.available = False
        return self

    def transform(self, texts: Sequence[str]) -> np.ndarray:
        if self.available and self.model is not None:
            return np.asarray(
                self.model.encode(
                    list(texts),
                    convert_to_numpy=True,
                    normalize_embeddings=True,
                    show_progress_bar=False,
                ),
                dtype=float,
            )
        return self.fallback.transform(texts)


class FraudVectorizer(BaseEstimator, TransformerMixin):
    def __init__(self, protected_domains: Optional[Dict[str, str]] = None, allow_live_lookup: bool = False):
        self.protected_domains = dict(protected_domains or PROTECTED_DOMAINS)
        self.allow_live_lookup = allow_live_lookup
        self.text_vectorizer = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            max_features=5000,
            min_df=1,
            sublinear_tf=True,
        )
        self.url_vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=2500,
            min_df=1,
            sublinear_tf=True,
        )
        self.context_vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=1500,
            min_df=1,
            sublinear_tf=True,
        )
        self.domain_features = DomainFeatureExtractor(
            protected_domains=self.protected_domains,
            cache=DomainReputationCache(),
            allow_live_lookup=allow_live_lookup,
        )
        self.embedding_extractor = SentenceEmbeddingExtractor()
        self._feature_names = np.array([], dtype=object)

    def fit(self, records: Sequence[Dict[str, str]], y=None):
        texts = [self._prepare_text(record) for record in records]
        urls = [self._prepare_url(record) for record in records]
        contexts = [self._prepare_context(record) for record in records]
        self.text_vectorizer.fit(texts)
        self.url_vectorizer.fit(urls)
        self.context_vectorizer.fit(contexts)
        self.embedding_extractor.fit(contexts)

        feature_names: List[str] = []
        feature_names.extend(f"text::{name}" for name in self.text_vectorizer.get_feature_names_out())
        feature_names.extend(f"url::{name}" for name in self.url_vectorizer.get_feature_names_out())
        feature_names.extend(f"context::{name}" for name in self.context_vectorizer.get_feature_names_out())
        feature_names.extend(f"domain::{name}" for name in self.domain_features.feature_names)
        embedding_width = self.embedding_extractor.transform(["bootstrap"]).shape[1]
        feature_names.extend(f"embedding::{index}" for index in range(embedding_width))
        self._feature_names = np.array(feature_names, dtype=object)
        return self

    def transform(self, records: Sequence[Dict[str, str]]):
        return self.transform_records(records)

    def fit_transform(self, records: Sequence[Dict[str, str]], y=None):
        self.fit(records, y=y)
        return self.transform_records(records)

    def transform_records(self, records: Sequence[Dict[str, str]]):
        texts = [self._prepare_text(record) for record in records]
        urls = [self._prepare_url(record) for record in records]
        contexts = [self._prepare_context(record) for record in records]
        text_features = self.text_vectorizer.transform(texts)
        url_features = self.url_vectorizer.transform(urls)
        context_features = self.context_vectorizer.transform(contexts)
        domain_features = csr_matrix(self.domain_features.transform(records))
        embedding_features = csr_matrix(self.embedding_extractor.transform(contexts))
        return hstack([text_features, url_features, context_features, domain_features, embedding_features], format="csr")

    def get_feature_names_out(self):
        return self._feature_names

    def explain_record(self, record: Dict[str, str], top_n: int = 8):
        row = self.transform_records([record]).toarray()[0]
        items = []
        for name, value in zip(self._feature_names, row):
            if abs(float(value)) > 0:
                items.append({"feature": str(name), "importance": float(value)})
        items.sort(key=lambda item: abs(item["importance"]), reverse=True)

        domain_items = self.domain_features.explain(record, top_n=top_n)
        merged = domain_items + items
        deduped = []
        seen = set()
        for item in merged:
            if item["feature"] in seen:
                continue
            seen.add(item["feature"])
            deduped.append(item)
            if len(deduped) >= top_n:
                break
        return deduped

    @staticmethod
    def _prepare_text(record: Dict[str, str]) -> str:
        return (record.get("text", "") or "").strip().lower()

    @staticmethod
    def _prepare_url(record: Dict[str, str]) -> str:
        url = record.get("url", "") or ""
        details = split_domain(url) if url else {"host": "", "path": ""}
        return f"{details.get('host', '')} {details.get('path', '')}".strip()

    def _prepare_context(self, record: Dict[str, str]) -> str:
        text = self._prepare_text(record)
        url = self._prepare_url(record)
        details = split_domain(record.get("url", "") or "")
        domain_tokens = " ".join([details.get("domain", ""), details.get("suffix", "")]).strip()
        return f"{text} [url] {url} [domain] {domain_tokens}".strip()


def generate_dataset() -> pd.DataFrame:
    genuine_templates = [
        "Official farmer scheme details are available at {url}. Registration opens next week.",
        "किसान योजना की आधिकारिक जानकारी यहाँ देखें: {url}",
        "Use the official portal {url} to check subsidy status.",
        "Bank branch locator and service updates are available at {url}.",
        "Aaj ka official update sirf {url} par publish hua hai.",
        "Please review the government FAQ on {url} before applying.",
    ]
    fraud_templates = [
        "URGENT: verify your farmer subsidy immediately at {url} or benefits will stop.",
        "Lottery winner for government scheme, click {url} and pay processing fee now.",
        "KYC failed. Update bank account at {url} within 2 hours.",
        "तुरंत सत्यापन करें: {url} नहीं तो आपकी सब्सिडी बंद हो जाएगी।",
        "Free bonus for selected farmers. Claim at {url} now.",
        "Aaj hi account unlock karne ke liye {url} open karo.",
    ]
    neutral_templates = [
        "Market prices were discussed in today's community meeting.",
        "General advisory: rainfall may affect crop planning this week.",
        "बस सामान्य जानकारी साझा कर रहा हूँ, कोई कार्रवाई जरूरी नहीं है।",
        "New post about irrigation tips and soil testing methods.",
        "Community event timing may change after local confirmation.",
        "Kisan workshop schedule will be updated later.",
    ]

    genuine_records: List[Dict[str, str]] = []
    fraud_records: List[Dict[str, str]] = []
    neutral_records: List[Dict[str, str]] = []

    for domain, category in PROTECTED_DOMAINS.items():
        genuine_url = f"https://{domain}/scheme"
        for template in genuine_templates:
            text = template.format(url=genuine_url)
            if category == "banking":
                text = text.replace("farmer scheme", "bank service").replace("subsidy", "account")
            genuine_records.append({"text": text, "url": genuine_url, "label": "genuine"})

        for strategy in ["swap", "drop", "homoglyph", "tld"]:
            fake_domain = build_typosquat_domain(domain, strategy)
            if domain == "farmer.gov.in":
                fake_domain = "former.gov.in"
            fake_url = f"https://{fake_domain}/verify"
            for template in fraud_templates:
                fraud_records.append({"text": template.format(url=fake_url), "url": fake_url, "label": "fraud"})

    extra_fraud = [
        {"text": "Gov relief payout pending. Open https://pmkissan.xyz/claim and confirm Aadhaar now.", "url": "https://pmkissan.xyz/claim", "label": "fraud"},
        {"text": "गूगल फॉर्म सत्यापन के लिए https://g00gle.com/verify खोलें", "url": "https://g00gle.com/verify", "label": "fraud"},
        {"text": "Use https://sbl.co.in/login to unlock your SBI reward bonus.", "url": "https://sbl.co.in/login", "label": "fraud"},
        {"text": "Official gov lottery payment at https://farmer-help.top/winner", "url": "https://farmer-help.top/winner", "label": "fraud"},
    ]
    fraud_records.extend(extra_fraud)

    extra_genuine = [
        {"text": "Scheme application guide: https://farmer.gov.in/scheme", "url": "https://farmer.gov.in/scheme", "label": "genuine"},
        {"text": "PM Kisan beneficiary list is available on https://pmkisan.gov.in", "url": "https://pmkisan.gov.in", "label": "genuine"},
        {"text": "Visit https://onlinesbi.sbi for official net banking access.", "url": "https://onlinesbi.sbi", "label": "genuine"},
    ]
    genuine_records.extend(extra_genuine)

    for template in neutral_templates:
        neutral_records.append({"text": template, "url": "", "label": "neutral"})
        neutral_records.append({"text": f"{template} More info at https://example.org/article", "url": "https://example.org/article", "label": "neutral"})

    records = genuine_records + fraud_records + neutral_records
    dataset = pd.DataFrame(records)
    dataset = dataset.sample(frac=1.0, random_state=RANDOM_SEED).reset_index(drop=True)
    return dataset


@dataclass
class TrainingArtifacts:
    model_bundle: Dict[str, object]
    vectorizer: FraudVectorizer
    metrics: Dict[str, object]


def choose_classifier(num_classes: int):
    if XGBClassifier is not None:
        classifier = XGBClassifier(
            n_estimators=220,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="multi:softprob",
            eval_metric="mlogloss",
            random_state=RANDOM_SEED,
            n_jobs=1,
        )
        return classifier, "xgboost"

    classifier = LogisticRegression(
        max_iter=2500,
        class_weight="balanced",
        random_state=RANDOM_SEED,
    )
    return classifier, "logistic_regression_fallback"


def print_matrix(labels: Sequence[str], matrix: np.ndarray, title: str) -> None:
    print(f"\n{title}")
    header = "predicted -> " + " | ".join(f"{label:>8}" for label in labels)
    print(header)
    print("-" * len(header))
    for label, row in zip(labels, matrix):
        values = " | ".join(f"{value:>8}" for value in row)
        print(f"{label:>12} | {values}")


def evaluate_url_binary(y_true: Sequence[str], y_pred: Sequence[str], urls: Sequence[str]) -> Dict[str, object]:
    filtered_true = []
    filtered_pred = []
    for actual, predicted, url in zip(y_true, y_pred, urls):
        if not url:
            continue
        filtered_true.append("fraud" if actual == "fraud" else "non_fraud")
        filtered_pred.append("fraud" if predicted == "fraud" else "non_fraud")

    labels = ["fraud", "non_fraud"]
    matrix = confusion_matrix(filtered_true, filtered_pred, labels=labels)
    precision, recall, f1, _ = precision_recall_fscore_support(
        filtered_true,
        filtered_pred,
        labels=["fraud"],
        average=None,
        zero_division=0,
    )
    return {
        "labels": labels,
        "confusion_matrix": matrix.tolist(),
        "precision_fraud": float(precision[0]),
        "recall_fraud": float(recall[0]),
        "f1_fraud": float(f1[0]),
        "sample_count": len(filtered_true),
    }


def train_model_v2() -> TrainingArtifacts:
    MODELS_DIR.mkdir(exist_ok=True)
    dataset = generate_dataset()

    print("=" * 72)
    print("Training fraud detector v2")
    print("=" * 72)
    print(f"Dataset size: {len(dataset)}")
    print(f"Class counts: {dict(Counter(dataset['label']))}")

    train_records, test_records = train_test_split(
        dataset.to_dict("records"),
        test_size=0.25,
        random_state=RANDOM_SEED,
        stratify=dataset["label"],
    )

    vectorizer = FraudVectorizer(
        protected_domains=PROTECTED_DOMAINS,
        allow_live_lookup=os.getenv("ENABLE_LIVE_WHOIS", "0") == "1",
    )
    x_train = vectorizer.fit_transform(train_records)
    x_test = vectorizer.transform_records(test_records)

    label_encoder = LabelEncoder()
    y_train = label_encoder.fit_transform([record["label"] for record in train_records])
    y_test = label_encoder.transform([record["label"] for record in test_records])

    classifier, classifier_name = choose_classifier(num_classes=len(label_encoder.classes_))
    classifier.fit(x_train, y_train)

    probabilities = classifier.predict_proba(x_test)
    y_pred = np.argmax(probabilities, axis=1)
    predicted_labels = label_encoder.inverse_transform(y_pred)
    true_labels = label_encoder.inverse_transform(y_test)

    labels = list(label_encoder.classes_)
    matrix = confusion_matrix(true_labels, predicted_labels, labels=labels)
    report = classification_report(true_labels, predicted_labels, labels=labels, output_dict=True, zero_division=0)
    url_binary = evaluate_url_binary(true_labels, predicted_labels, [record.get("url", "") for record in test_records])

    print("\nClassification report:")
    print(classification_report(true_labels, predicted_labels, labels=labels, zero_division=0))
    print_matrix(labels, matrix, "Multiclass confusion matrix")
    print_matrix(url_binary["labels"], np.array(url_binary["confusion_matrix"]), "URL fraud confusion matrix")
    print(
        "URL fraud precision={:.4f} recall={:.4f} f1={:.4f}".format(
            url_binary["precision_fraud"],
            url_binary["recall_fraud"],
            url_binary["f1_fraud"],
        )
    )

    model_bundle = {
        "classifier": classifier,
        "label_encoder": label_encoder,
        "metadata": {
            "artifact_version": "v2",
            "classifier": classifier_name,
            "embedding_backend": vectorizer.embedding_extractor.backend,
            "protected_domains": sorted(PROTECTED_DOMAINS.keys()),
            "suspicious_tlds": sorted(SUSPICIOUS_TLDS),
            "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        },
    }

    metrics = {
        "labels": labels,
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "url_binary_metrics": url_binary,
        "dataset_size": int(len(dataset)),
        "class_counts": {key: int(value) for key, value in Counter(dataset["label"]).items()},
        "average_confidence": float(np.mean(np.max(probabilities, axis=1))),
        "examples": {
            "legitimate": "https://farmer.gov.in/scheme",
            "fraud": "https://former.gov.in/verify",
        },
    }

    vectorizer.domain_features.cache.save()
    joblib.dump(model_bundle, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    with METRICS_PATH.open("w", encoding="utf-8") as handle:
        json.dump(metrics, handle, indent=2, ensure_ascii=False)

    print(f"\nSaved model: {MODEL_PATH}")
    print(f"Saved vectorizer: {VECTORIZER_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")
    return TrainingArtifacts(model_bundle=model_bundle, vectorizer=vectorizer, metrics=metrics)


def run_smoke_predictions():
    from ml_model import MLFraudDetector

    detector = MLFraudDetector(str(MODEL_PATH), str(VECTORIZER_PATH))
    samples = [
        {"text": "Official farmer subsidy guide is published here.", "url": "https://farmer.gov.in/scheme"},
        {"text": "URGENT verify your subsidy now or account will be blocked.", "url": "https://former.gov.in/verify"},
        {"text": "तुरंत केवाईसी अपडेट करें", "url": "https://pmkissan.xyz/claim"},
    ]
    print("\nSmoke predictions:")
    for sample in samples:
        details = detector.predict_details(sample["text"], url=sample["url"])
        print(f"  url={sample['url']}")
        print(f"  label={details['label']} confidence={details['confidence']:.4f}")
        print(f"  top_signals={details['explanation'][:4]}")


def main():
    artifacts = train_model_v2()
    _ = artifacts
    run_smoke_predictions()


if __name__ == "__main__":
    main()
