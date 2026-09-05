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

"""Authorization tests for the datasource lookup in GetExploreCommand."""

from collections.abc import Iterator
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from superset.commands.explore.get import GetExploreCommand
from superset.commands.explore.parameters import CommandParameters
from superset.exceptions import SupersetSecurityException
from superset.utils.core import DatasourceType


def _datasource(datasource_id: int, name: str) -> MagicMock:
    datasource = MagicMock()
    datasource.id = datasource_id
    datasource.type = DatasourceType.TABLE
    datasource.name = name
    datasource.default_endpoint = None
    datasource.data = {
        "type": DatasourceType.TABLE,
        "name": name,
        "columns": [{"column_name": "secret_col"}],
        "metrics": [],
        "database": {"id": 1, "backend": "postgresql", "name": "prod"},
    }
    return datasource


def _chart(chart_id: int, datasource_id: int) -> MagicMock:
    slc = MagicMock()
    slc.id = chart_id
    slc.datasource_id = datasource_id
    slc.datasource_type = DatasourceType.TABLE
    slc.form_data = {"datasource": f"{datasource_id}__table", "viz_type": "table"}
    slc.editors = []
    slc.dashboards = []
    slc.created_by = None
    slc.changed_by = None
    slc.created_on_humanized = ""
    slc.changed_on_humanized = ""
    return slc


def _params(
    slice_id: Optional[int] = None,
    datasource_id: Optional[int] = None,
    datasource_type: Optional[str] = None,
) -> CommandParameters:
    return CommandParameters(
        permalink_key=None,
        form_data_key=None,
        datasource_id=datasource_id,
        datasource_type=datasource_type,
        slice_id=slice_id,
    )


def _security_manager(allowed_datasource_ids: set[int]) -> MagicMock:
    def raise_for_access(
        datasource: Optional[MagicMock] = None,
        chart: Optional[MagicMock] = None,
        **_: Any,
    ) -> None:
        if datasource is not None and datasource.id not in allowed_datasource_ids:
            raise SupersetSecurityException(MagicMock())

    sm = MagicMock()
    sm.raise_for_access.side_effect = raise_for_access
    sm.can_access.return_value = False
    return sm


@pytest.fixture
def request_ctx(app: Flask) -> Iterator[None]:
    with app.test_request_context("/api/v1/explore/"):
        yield


def _run(
    params: CommandParameters,
    datasources: dict[int, MagicMock],
    slc: Optional[MagicMock],
    sm: MagicMock,
    request_form_data: Optional[dict[str, Any]] = None,
) -> Optional[dict[str, Any]]:
    """Run the command, emulating ``get_form_data`` merge semantics.

    ``request_form_data`` stands in for the ``form_data`` request argument,
    which is layered on top of the chart's stored form_data.
    """

    def get_datasource(_: str, datasource_id: int) -> MagicMock:
        return datasources[datasource_id]

    def get_form_data(**kwargs: Any) -> tuple[dict[str, Any], Optional[MagicMock]]:
        form_data = dict(kwargs.get("initial_form_data") or {})
        form_data.update(request_form_data or {})
        if slc is not None:
            merged = dict(slc.form_data)
            merged.update(form_data)
            form_data = merged
        return form_data, slc

    with (
        patch(
            "superset.commands.explore.get.DatasourceDAO.get_datasource",
            side_effect=get_datasource,
        ),
        patch("superset.commands.explore.get.get_form_data", side_effect=get_form_data),
        patch("superset.commands.explore.get.security_manager", sm),
        patch("superset.commands.explore.get.DatasetDAO.get_rls_filters_for_dataset"),
        patch(
            "superset.commands.explore.get.sanitize_datasource_data",
            side_effect=lambda data: data,
        ),
    ):
        return GetExploreCommand(params).run()


@pytest.mark.usefixtures("request_ctx")
def test_datasource_lookup_denied_without_read_permission() -> None:
    """Metadata for an out-of-scope datasource ID must not be returned."""
    forbidden = _datasource(42, "hr_salaries")
    sm = _security_manager(allowed_datasource_ids={1})

    with pytest.raises(SupersetSecurityException):
        _run(
            _params(datasource_id=42, datasource_type="table"),
            {42: forbidden},
            None,
            sm,
        )

    sm.raise_for_access.assert_called_once_with(datasource=forbidden)


@pytest.mark.usefixtures("request_ctx")
def test_datasource_lookup_allowed_with_read_permission() -> None:
    allowed = _datasource(1, "public_sales")
    sm = _security_manager(allowed_datasource_ids={1})

    result = _run(
        _params(datasource_id=1, datasource_type="table"),
        {1: allowed},
        None,
        sm,
    )

    assert result is not None
    assert result["dataset"]["name"] == "public_sales"
    sm.raise_for_access.assert_called_once_with(datasource=allowed)


@pytest.mark.usefixtures("request_ctx")
def test_chart_access_does_not_grant_other_datasource() -> None:
    """A readable chart must not be usable to read a different datasource."""
    chart_datasource = _datasource(1, "public_sales")
    forbidden = _datasource(42, "hr_salaries")
    slc = _chart(7, datasource_id=1)
    sm = _security_manager(allowed_datasource_ids={1})

    with pytest.raises(SupersetSecurityException):
        _run(
            _params(slice_id=7),
            {1: chart_datasource, 42: forbidden},
            slc,
            sm,
            request_form_data={"datasource": "42__table"},
        )

    sm.raise_for_access.assert_called_once_with(datasource=forbidden)


@pytest.mark.usefixtures("request_ctx")
def test_chart_access_used_for_charts_own_datasource() -> None:
    chart_datasource = _datasource(1, "public_sales")
    slc = _chart(7, datasource_id=1)
    sm = _security_manager(allowed_datasource_ids=set())

    result = _run(
        _params(slice_id=7),
        {1: chart_datasource},
        slc,
        sm,
    )

    assert result is not None
    assert result["dataset"]["name"] == "public_sales"
    sm.raise_for_access.assert_called_once_with(chart=slc)
