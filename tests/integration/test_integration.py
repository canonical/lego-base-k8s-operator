#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import shutil
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("tests/integration/acme-tester/metadata.yaml").read_text())
APP_NAME = METADATA["name"]
TLS_LIB_PATH = "lib/charms/tls_certificates_interface/v1/tls_certificates.py"
ACME_CLIENT_LIB_PATH = "lib/charms/acme_client_operator/v0/acme_client.py"
TESTER_CHARM_DIR = "tests/integration/acme-tester"


def copy_lib_content() -> None:
    shutil.copyfile(src=TLS_LIB_PATH, dst=f"{TESTER_CHARM_DIR}/{TLS_LIB_PATH}")
    shutil.copyfile(src=TESTER_CHARM_DIR, dst=f"{TESTER_CHARM_DIR}/{ACME_CLIENT_LIB_PATH}")


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    copy_lib_content()
    charm = await ops_test.build_charm("tests/integration/acme-tester")
    resources = {"lego-image": METADATA["resources"]["lego-image"]["upstream-source"]}
    await ops_test.model.deploy(
        charm, resources=resources, application_name=APP_NAME, series="focal"
    )

    # issuing dummy update_status just to trigger an event
    async with ops_test.fast_forward():
        await ops_test.model.wait_for_idle(
            apps=[APP_NAME],
            status="active",
            raise_on_blocked=True,
            timeout=1000,
        )
        assert ops_test.model.applications[APP_NAME].units[0].workload_status == "active"
