import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict
from urllib.request import urlopen

from jose import jws, JWSError

from .exceptions import VerificationFailure


def now_utc_seconds():
    return int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())


def get_cache_control_max_age(http_info_message):
    return int(http_info_message.get("cache-control").split(",")[1].split("=")[1])


@dataclass
class GoogleOpenIdData:
    max_age: int
    configuration: Dict


def get_google_well_known_openid() -> GoogleOpenIdData:
    with urlopen("https://accounts.google.com/.well-known/openid-configuration") as stream:
        if stream.getcode() != 200:
            raise RuntimeError("Could not load google well known OpenID configurations!")
        max_age = get_cache_control_max_age(stream.info())
        return GoogleOpenIdData(max_age, json.loads(stream.read()))


@dataclass
class GoogleJWKData:
    max_age: int
    jwk_set: Dict


def get_google_jwk(jwks_uri: str) -> GoogleJWKData:
    with urlopen(jwks_uri) as stream:
        if stream.getcode() != 200:
            raise RuntimeError("Could not load google oauth certs!")
        max_age = get_cache_control_max_age(stream.info())
        return GoogleJWKData(max_age, json.loads(stream.read()))


class JWKCache:
    def __init__(self):
        self.last_refresh = 0
        self.jwk_data = None

    @property
    def expiration(self) -> int:
        if self.jwk_data is None:
            return 0
        else:
            return self.last_refresh + self.jwk_data.max_age

    def fetch_jwk_set(self, jwks_uri):
        now = now_utc_seconds()
        if self.expiration <= now:
            self.jwk_data = get_google_jwk(jwks_uri)
            self.last_refresh = now
        return self.jwk_data.jwk_set


class OpenIdCache:
    def __init__(self):
        self.last_refresh = 0
        self.openid_data = None

    @property
    def expiration(self) -> int:
        if self.openid_data is None:
            return 0
        else:
            return self.last_refresh + self.openid_data.max_age

    def fetch_configuration(self):
        now = now_utc_seconds()
        if self.expiration <= now:
            self.openid_data = get_google_well_known_openid()
            self.last_refresh = now
        return self.openid_data.configuration


class GoogleJWT:
    def __init__(self, google_client_id, hosted_domain):
        self._google_client_id = google_client_id
        self._hosted_domain = hosted_domain
        self._jwk = JWKCache()
        self._openid = OpenIdCache()

    @property
    def google_client_id(self):
        return self._google_client_id

    @property
    def hosted_domain(self):
        return self._hosted_domain

    @property
    def jwk_set(self):
        openid_configs = self._openid.fetch_configuration()
        return self._jwk.fetch_jwk_set(openid_configs["jwks_uri"])

    def verify_google_token(self, token) -> Dict:
        try:
            # noinspection PyTypeChecker
            jwt_payload = jws.verify(token, self.jwk_set, algorithms="RS256")
        except JWSError:
            raise VerificationFailure("Verification failed.")

        jwt_payload = json.loads(jwt_payload)
        now = datetime.utcnow()
        if jwt_payload["aud"] != self.google_client_id:
            raise VerificationFailure("Invalid audience.")
        if jwt_payload["iss"] not in {"accounts.google.com", "https://accounts.google.com"}:
            raise VerificationFailure("Invalid issuer.")
        if datetime.utcfromtimestamp(jwt_payload["exp"]) <= now:
            raise VerificationFailure("Token expired.")
        if "hd" not in jwt_payload or jwt_payload["hd"] != self.hosted_domain:
            raise VerificationFailure("Invalid G-suite domain.")

        return jwt_payload
