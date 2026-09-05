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
from __future__ import annotations

import io
import json
import logging
import pickle
from abc import ABC, abstractmethod
from typing import Any, TypedDict, Union
from uuid import UUID

from marshmallow import Schema, ValidationError

from superset.key_value.exceptions import (
    KeyValueCodecDecodeException,
    KeyValueCodecEncodeException,
)
from superset.utils.backports import StrEnum

logger = logging.getLogger(__name__)

Key = Union[int, UUID]


def log_codec_event(
    codec: str,
    operation: str,
    outcome: str,
    level: int = logging.DEBUG,
    **details: Any,
) -> None:
    """Emit a structured audit log entry for a key-value codec decision point.

    Every entry carries ``codec``, ``operation`` and ``outcome`` (plus any
    extra ``details``) both in the message and in the record's ``extra`` so
    structured log handlers can index them.
    """
    event = {"codec": codec, "operation": operation, "outcome": outcome, **details}
    logger.log(
        level,
        "key_value codec event: %s",
        " ".join(f"{k}={v}" for k, v in event.items()),
        extra={"key_value_codec_event": event},
    )


class KeyValueFilter(TypedDict, total=False):
    resource: str
    id: int | None
    uuid: UUID | None


class KeyValueResource(StrEnum):
    APP = "app"
    DASHBOARD_PERMALINK = "dashboard_permalink"
    EXPLORE_PERMALINK = "explore_permalink"
    METASTORE_CACHE = "superset_metastore_cache"
    LOCK = "lock"
    PKCE_CODE_VERIFIER = "pkce_code_verifier"
    SQLLAB_PERMALINK = "sqllab_permalink"


class SharedKey(StrEnum):
    DASHBOARD_PERMALINK_SALT = "dashboard_permalink_salt"
    EXPLORE_PERMALINK_SALT = "explore_permalink_salt"
    SQLLAB_PERMALINK_SALT = "sqllab_permalink_salt"
    # Monotonically increasing version used to revoke outstanding guest tokens.
    # Bumping it invalidates every guest token minted with a lower version.
    GUEST_TOKEN_REVOCATION_VERSION = "guest_token_revocation_version"  # noqa: S105
    # Per-deployment retention window (days) for purging soft-deleted entities.
    # Read live each run by deletion_retention.purge_soft_deleted; falls back to
    # SOFT_DELETE_RETENTION_DAYS when unset. 0 disables the purge.
    SOFT_DELETE_RETENTION_DAYS = "soft_delete_retention_days"


class KeyValueCodec(ABC):
    @abstractmethod
    def encode(self, value: Any) -> bytes: ...

    @abstractmethod
    def decode(self, value: bytes) -> Any: ...


class JsonKeyValueCodec(KeyValueCodec):
    def encode(self, value: dict[Any, Any]) -> bytes:
        try:
            return bytes(json.dumps(value), encoding="utf-8")
        except TypeError as ex:
            raise KeyValueCodecEncodeException(str(ex)) from ex

    def decode(self, value: bytes) -> dict[Any, Any]:
        try:
            return json.loads(value)
        except TypeError as ex:
            raise KeyValueCodecDecodeException(str(ex)) from ex


# (module, qualname) pairs the pickle codec is allowed to reconstruct. Only
# plain data containers and value types are permitted; any other global
# reference (functions, classes with side-effecting constructors, ``os``,
# ``subprocess`` ...) is rejected before it can be instantiated.
PICKLE_SAFE_GLOBALS: frozenset[tuple[str, str]] = frozenset(
    {
        ("builtins", "object"),
        ("builtins", "set"),
        ("builtins", "frozenset"),
        ("builtins", "complex"),
        ("builtins", "bytearray"),
        ("builtins", "range"),
        ("builtins", "slice"),
        ("collections", "OrderedDict"),
        ("collections", "defaultdict"),
        ("collections", "deque"),
        ("datetime", "date"),
        ("datetime", "datetime"),
        ("datetime", "time"),
        ("datetime", "timedelta"),
        ("datetime", "timezone"),
        ("decimal", "Decimal"),
        ("uuid", "UUID"),
        ("_codecs", "encode"),
    }
)


class ForbiddenPickleGlobalError(pickle.UnpicklingError):
    """Raised when a pickle stream references a global outside the allowlist."""


class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only resolves globals listed in ``PICKLE_SAFE_GLOBALS``."""

    def find_class(self, module: str, name: str) -> Any:
        if (module, name) in PICKLE_SAFE_GLOBALS:
            return super().find_class(module, name)
        raise ForbiddenPickleGlobalError(
            f"Refusing to unpickle forbidden global {module}.{name}"
        )


class PickleKeyValueCodec(KeyValueCodec):
    """Pickle codec restricted to plain data types.

    Decoding never resolves arbitrary globals, so a tampered stored value
    cannot trigger code execution; it fails with
    :class:`KeyValueCodecDecodeException` instead. Encoding applies the same
    allowlist so a value that could not be read back is rejected with
    :class:`KeyValueCodecEncodeException` before it is ever persisted.
    """

    def encode(self, value: Any) -> bytes:
        try:
            encoded = pickle.dumps(value)
            RestrictedUnpickler(io.BytesIO(encoded)).load()
        except ForbiddenPickleGlobalError as ex:
            log_codec_event(
                "pickle",
                "encode",
                "rejected",
                level=logging.WARNING,
                value_type=type(value).__name__,
                error=str(ex),
            )
            raise KeyValueCodecEncodeException(str(ex)) from ex
        except (
            pickle.PickleError,
            TypeError,
            AttributeError,
            RecursionError,
        ) as ex:
            log_codec_event(
                "pickle",
                "encode",
                "error",
                level=logging.WARNING,
                value_type=type(value).__name__,
                error=type(ex).__name__,
            )
            raise KeyValueCodecEncodeException(str(ex)) from ex
        log_codec_event("pickle", "encode", "success", value_type=type(value).__name__)
        return encoded

    def decode(self, value: bytes) -> Any:
        try:
            decoded = RestrictedUnpickler(io.BytesIO(value)).load()
        except ForbiddenPickleGlobalError as ex:
            log_codec_event(
                "pickle",
                "decode",
                "rejected",
                level=logging.WARNING,
                size=len(value),
                error=str(ex),
            )
            raise KeyValueCodecDecodeException(str(ex)) from ex
        except (
            pickle.UnpicklingError,
            EOFError,
            TypeError,
            ValueError,
            AttributeError,
            IndexError,
        ) as ex:
            log_codec_event(
                "pickle",
                "decode",
                "error",
                level=logging.WARNING,
                size=len(value),
                error=type(ex).__name__,
            )
            raise KeyValueCodecDecodeException(str(ex)) from ex
        log_codec_event(
            "pickle", "decode", "success", value_type=type(decoded).__name__
        )
        return decoded


class BinaryKeyValueCodec(KeyValueCodec):
    """Identity codec for raw bytes; stored as-is, no transformation applied.

    JSON has no binary type, so a caller transporting this codec's value
    over a JSON transport (e.g. a REST API) must carry it as a base64
    string on the wire. That base64 encoding/decoding is a transport
    concern handled by the REST layer around this codec, not something
    this codec's `encode`/`decode` does itself.
    """

    def encode(self, value: bytes) -> bytes:
        return value

    def decode(self, value: bytes) -> bytes:
        return value


class MarshmallowKeyValueCodec(JsonKeyValueCodec):
    def __init__(self, schema: Schema):
        self.schema = schema

    def encode(self, value: dict[Any, Any]) -> bytes:
        try:
            obj = self.schema.dump(value)
            return super().encode(obj)
        except ValidationError as ex:
            raise KeyValueCodecEncodeException(message=str(ex)) from ex

    def decode(self, value: bytes) -> dict[Any, Any]:
        try:
            obj = super().decode(value)
            return self.schema.load(obj)
        except ValidationError as ex:
            raise KeyValueCodecEncodeException(message=str(ex)) from ex
