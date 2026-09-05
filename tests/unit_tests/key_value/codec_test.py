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
import collections
import logging
import os
import pickle
from collections import OrderedDict
from contextlib import nullcontext
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from unittest.mock import patch
from uuid import UUID

import pytest
from marshmallow import Schema

from superset.dashboards.permalink.schemas import DashboardPermalinkSchema
from superset.key_value.exceptions import (
    KeyValueCodecDecodeException,
    KeyValueCodecEncodeException,
)
from superset.key_value.types import (
    BinaryKeyValueCodec,
    JsonKeyValueCodec,
    MarshmallowKeyValueCodec,
    PickleKeyValueCodec,
)


@pytest.mark.parametrize(
    "input_,expected_result",
    [
        (
            {"foo": "bar"},
            {"foo": "bar"},
        ),
        (
            {"foo": (1, 2, 3)},
            {"foo": [1, 2, 3]},
        ),
        (
            {1, 2, 3},
            KeyValueCodecEncodeException(),
        ),
        (
            object(),
            KeyValueCodecEncodeException(),
        ),
    ],
)
def test_json_codec(input_: Any, expected_result: Any):
    cm = (
        pytest.raises(type(expected_result))
        if isinstance(expected_result, Exception)
        else nullcontext()
    )
    with cm:
        codec = JsonKeyValueCodec()
        encoded_value = codec.encode(input_)
        assert expected_result == codec.decode(encoded_value)


@pytest.mark.parametrize(
    "schema,input_,expected_result",
    [
        (
            DashboardPermalinkSchema(),
            {
                "dashboardId": "1",
                "state": {
                    "urlParams": [["foo", "bar"], ["foo", "baz"]],
                },
            },
            {
                "dashboardId": "1",
                "state": {
                    "urlParams": [("foo", "bar"), ("foo", "baz")],
                },
            },
        ),
        (
            DashboardPermalinkSchema(),
            {"foo": "bar"},
            KeyValueCodecEncodeException(),
        ),
    ],
)
def test_marshmallow_codec(schema: Schema, input_: Any, expected_result: Any):
    cm = (
        pytest.raises(type(expected_result))
        if isinstance(expected_result, Exception)
        else nullcontext()
    )
    with cm:
        codec = MarshmallowKeyValueCodec(schema)
        encoded_value = codec.encode(input_)
        assert expected_result == codec.decode(encoded_value)


@pytest.mark.parametrize(
    "input_,expected_result",
    [
        (
            {1, 2, 3},
            {1, 2, 3},
        ),
        (
            {"foo": 1, "bar": {1: (1, 2, 3)}, "baz": {1, 2, 3}},
            {
                "foo": 1,
                "bar": {1: (1, 2, 3)},
                "baz": {1, 2, 3},
            },
        ),
    ],
)
def test_pickle_codec(input_: Any, expected_result: Any):
    codec = PickleKeyValueCodec()
    encoded_value = codec.encode(input_)
    assert expected_result == codec.decode(encoded_value)


@pytest.mark.parametrize(
    "input_",
    [
        complex(1, 1),
        datetime(2024, 1, 1, 12, 30, tzinfo=timezone.utc),
        {"when": date(2024, 1, 1), "delta": timedelta(hours=1)},
        Decimal("1.25"),
        UUID("12345678-1234-5678-1234-567812345678"),
        OrderedDict(a=1, b=2),
        frozenset({1, 2}),
        b"\x00\xff",
        None,
    ],
)
def test_pickle_codec_allows_value_types(input_: Any):
    codec = PickleKeyValueCodec()
    assert codec.decode(codec.encode(input_)) == input_


class _Exploit:
    def __reduce__(self) -> tuple[Any, ...]:
        return (os.system, ("echo pwned",))


def test_pickle_codec_rejects_forbidden_globals(caplog):
    codec = PickleKeyValueCodec()
    payload = pickle.dumps(_Exploit())
    with caplog.at_level(logging.WARNING), patch("os.system") as system:
        with pytest.raises(KeyValueCodecDecodeException, match="forbidden global"):
            codec.decode(payload)
    system.assert_not_called()
    record = next(r for r in caplog.records if hasattr(r, "key_value_codec_event"))
    assert record.key_value_codec_event["operation"] == "decode"
    assert record.key_value_codec_event["outcome"] == "rejected"


def test_pickle_codec_rejects_arbitrary_classes():
    codec = PickleKeyValueCodec()
    payload = pickle.dumps(collections.Counter(a=1))
    with pytest.raises(KeyValueCodecDecodeException):
        codec.decode(payload)


def test_pickle_codec_rejects_truncated_payload(caplog):
    codec = PickleKeyValueCodec()
    payload = codec.encode({"foo": "bar"})[:-3]
    with caplog.at_level(logging.WARNING):
        with pytest.raises(KeyValueCodecDecodeException):
            codec.decode(payload)
    record = next(r for r in caplog.records if hasattr(r, "key_value_codec_event"))
    assert record.key_value_codec_event["outcome"] == "error"


def test_pickle_codec_encode_failure_raises_codec_exception():
    codec = PickleKeyValueCodec()
    with pytest.raises(KeyValueCodecEncodeException):
        codec.encode(lambda: None)


def test_pickle_codec_logs_structured_success_events(caplog):
    codec = PickleKeyValueCodec()
    with caplog.at_level(logging.DEBUG, logger="superset.key_value.types"):
        codec.decode(codec.encode({"foo": "bar"}))
    events = [
        r.key_value_codec_event
        for r in caplog.records
        if hasattr(r, "key_value_codec_event")
    ]
    assert [(e["operation"], e["outcome"]) for e in events] == [
        ("encode", "success"),
        ("decode", "success"),
    ]
    assert all(e["codec"] == "pickle" for e in events)


def test_binary_codec_encode():
    codec = BinaryKeyValueCodec()
    raw = b"\x00\x01binary\xffdata"
    assert codec.encode(raw) == raw


def test_binary_codec_round_trips():
    codec = BinaryKeyValueCodec()
    raw = b"\x00\x01binary\xffdata"
    assert codec.decode(raw) == raw
    assert codec.encode(codec.decode(raw)) == raw
