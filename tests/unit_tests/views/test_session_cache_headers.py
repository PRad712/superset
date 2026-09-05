# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""
Regression coverage for CVE-2026-27205 (Flask < 3.1.3 did not add ``Vary: Cookie``
when the session was merely accessed) and Superset's compensating
``Cache-Control: private`` for session-dependent responses.
"""

from importlib.metadata import version
from typing import Any

from flask import Response, session
from packaging.version import Version


def test_flask_version_includes_vary_cookie_fix() -> None:
    assert Version(version("flask")) >= Version("3.1.3")


def test_session_read_sets_vary_cookie_and_private_cache_control(
    client: Any,
) -> None:
    """A response that only reads the session must not be cacheable by shared caches."""
    response = client.get("/api/v1/me/")

    assert response.status_code == 401
    assert "Cookie" in response.vary
    assert response.cache_control.private is True


def test_explicit_cache_control_is_preserved(app: Any, client: Any) -> None:
    """Views that declare their own caching policy (e.g. immutable assets) win."""

    def public_asset() -> Response:
        session.get("_user_id")
        response = Response("asset")
        response.cache_control.public = True
        response.cache_control.max_age = 60
        return response

    app.view_functions["public_asset_for_test"] = public_asset
    app.url_map.add(
        app.url_rule_class("/_test/public-asset", endpoint="public_asset_for_test")
    )

    response = client.get("/_test/public-asset")

    assert response.status_code == 200
    assert response.cache_control.public is True
    assert response.cache_control.private is None
    assert "Cookie" in response.vary
