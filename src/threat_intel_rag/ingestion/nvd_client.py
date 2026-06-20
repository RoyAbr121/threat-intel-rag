from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import datetime

import httpx
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential


class CveDescription(BaseModel):
    lang: str
    value: str


class CvssData(BaseModel):
    base_score: float = Field(alias="baseScore")
    base_severity: str = Field(alias="baseSeverity")
    model_config = {"populate_by_name": True}


class CvssMetricV31(BaseModel):
    cvss_data: CvssData = Field(alias="cvssData")
    model_config = {"populate_by_name": True}


class CveMetrics(BaseModel):
    cvss_metric_v31: list[CvssMetricV31] = Field(
        alias="cvssMetricV31", default_factory=list
    )

    model_config = {"populate_by_name": True}


class CveReference(BaseModel):
    url: str


class CveDetail(BaseModel):
    id: str
    published: datetime
    last_modified: datetime = Field(alias="lastModified")
    descriptions: list[CveDescription]
    metrics: CveMetrics = Field(default_factory=CveMetrics)
    references: list[CveReference]

    model_config = {"populate_by_name": True}


class CveItem(BaseModel):
    cve: CveDetail


class NvdResponse(BaseModel):
    results_per_page: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    vulnerabilities: list[CveItem]

    model_config = {"populate_by_name": True}


class NvdClient:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    PAGE_SIZE = 2000

    def __init__(self, api_key: str | None = None) -> None:
        headers = {"apiKey": api_key} if api_key else {}
        self._client = httpx.AsyncClient(headers=headers, timeout=30.0)

    async def __aenter__(self) -> NvdClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._client.aclose()

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=4, max=30),
    )
    async def _fetch_page(
        self,
        start_index: int,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> NvdResponse:
        params: dict[str, str | int] = {
            "startIndex": start_index,
            "resultsPerPage": self.PAGE_SIZE,
        }

        if start_date is not None:
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        if end_date is not None:
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        response = await self._client.get(self.BASE_URL, params=params)
        response.raise_for_status()

        return NvdResponse.model_validate(response.json())

    async def iter_cves(
        self, start_date: datetime | None = None, end_date: datetime | None = None
    ) -> AsyncIterator[CveDetail]:
        start = 0

        while True:
            page = await self._fetch_page(
                start, start_date=start_date, end_date=end_date
            )

            for item in page.vulnerabilities:
                yield item.cve

            start += len(page.vulnerabilities)

            if start >= page.total_results:
                break

            await asyncio.sleep(6)
