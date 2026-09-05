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
import logging
import pickle
from collections import Counter
from unittest.mock import MagicMock, patch
from uuid import uuid4

from superset.key_value.types import PickleKeyValueCodec


def test_get_treats_undecodable_entry_as_cache_miss(caplog) -> None:
    """A stored value the restricted codec refuses is a miss, not an error."""
    from superset.extensions.metastore_cache import SupersetMetastoreCache

    cache = SupersetMetastoreCache(namespace=uuid4(), codec=PickleKeyValueCodec())
    legacy_entry = MagicMock()
    legacy_entry.is_expired.return_value = False
    legacy_entry.value = pickle.dumps(Counter(a=1))

    with (
        patch(
            "superset.daos.key_value.KeyValueDAO.get_entry",
            return_value=legacy_entry,
        ),
        caplog.at_level(logging.WARNING),
    ):
        assert cache.get("legacy") is None
        assert cache.has("legacy") is False

    assert any("outcome=decode_failed" in r.message for r in caplog.records)
