import urllib.parse
from dataclasses import dataclass

import requests


@dataclass
class OAuthUserInfo:
    id: str
    name: str
    email: str


class OAuth:
    def __init__(self, redirect_uri: str):
        self.redirect_uri = redirect_uri

    def get_authorization_url(self):
        raise NotImplementedError()


class CMBCOAuth(OAuth):
    _AUTH_URL = 'https://low-code-content.paas.cmbchina.com/front/view?pageId=o7i111c7Bw'

    def get_authorization_url(self):
        return self._AUTH_URL
