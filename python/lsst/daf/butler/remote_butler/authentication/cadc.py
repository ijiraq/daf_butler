# This file is part of daf_butler.
#
# Developed for the LSST Data Management System.
# This product includes software developed by the LSST Project
# (http://www.lsst.org).
# See the COPYRIGHT file at the top-level directory of this distribution
# for details of code ownership.
#
# This software is dual licensed under the GNU General Public License and also
# under a 3-clause BSD license. Recipients may choose which of these licenses
# to use; please see the files gpl-3.0.txt and/or bsd_license.txt,
# respectively.  If you choose the GPL option then the following text applies
# (but note that there is still no warranty even if you opt for BSD instead):
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations
import os
import base64
import re
import time
import logging
import httpx
import ssl
from pathlib import Path

from .interface import RemoteButlerAuthenticationProvider

OPENID_CONFIG_URL = os.getenv("OPENID_CONFIG_URL",
                                   "https://ws-cadc.canfar.net/ac/.well-known/openid-configuration")
SSL_PROXY_FILENAME = os.getenv("SSL_PROXY_FILENAME",
                               os.path.join(Path.home(),".ssl","cadcproxy.pem"))
TOKEN_ENV_VAR = "CADC_TOKEN"

def get_cadc_authorize_url() -> str:
    """Query the openid configuration to get the authorization URL."""
    try:
        response = httpx.get(OPENID_CONFIG_URL)
        response.raise_for_status()
        config = response.json()
        return config["authorization_endpoint"]
    except httpx.RequestError as e:
        raise RuntimeError(f"Failed to find authorization URL at {OPENID_CONFIG_URL}") from e


class CadcAuthenticationProvider(RemoteButlerAuthenticationProvider):
    """Provide HTTP headers required for authenticating the user at the
    Canadian Astronomy Data Centre.
    """

    # NOTE -- This object needs to be pickleable. It will sometimes be
    # serialized and transferred to another process to execute file transfers.

    def __init__(self) -> None:
        self._token = os.environ.get(TOKEN_ENV_VAR)

    @property
    def token(self) -> str:
        if self._token_is_valid:
            return self._token

        # Get a new token from authorize endpoint and ssl cert.
        if not os.path.exists(SSL_PROXY_FILENAME):
            raise FileNotFoundError(f"Proxy certificate file not found: {SSL_PROXY_FILENAME}")
        ctx = ssl.create_default_context()
        ctx.load_cert_chain(certfile=SSL_PROXY_FILENAME)  # Optionally also keyfile or password.
        params = {'response_type': 'token'}
        try:
            auth_url = get_cadc_authorize_url()
            response = httpx.Client(verify=ctx).get(auth_url, params=params)
            response.raise_for_status()
        except httpx.RequestError as e:
            raise RuntimeError("Could not retrieve token") from e

        # update the token in the environment variable for this session.
        os.environ[TOKEN_ENV_VAR] = response.text
        # update the internal token variable
        self._token = os.environ.get(TOKEN_ENV_VAR)
        # self-reference to ensure that the token is valid
        return self.token

    @property
    def _token_is_valid(self) -> bool:
        if self._token is None:
            return False
        try:
            # Decode the base64 string
            decoded_bytes = base64.b64decode(self._token)
            decoded_str = decoded_bytes.decode('utf-8')

            # Search for expirytime using a regular expression
            match = re.search(r"expirytime=(\d+)", decoded_str)
            if not match:
                return False

            exp_time = int(match.group(1))
            current_time = int(time.time())
            return exp_time > current_time
        except Exception as e:
            logging.debug(e)
            return False

    def get_server_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}

    def get_datastore_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}