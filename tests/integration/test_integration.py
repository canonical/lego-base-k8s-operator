#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import shutil
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("tests/integration/acme-operator/metadata.yaml").read_text())
APP_NAME = METADATA["name"]
TLS_LIB_PATH = "lib/charms/tls_certificates_interface/v1/tls_certificates.py"
ACME_CLIENT_LIB_PATH = "lib/charms/acme_client_operator/v0/acme_client.py"
ACME_OPERATOR_DIR = "tests/integration/acme-operator"


def copy_lib_content() -> None:
    shutil.copyfile(src=TLS_LIB_PATH, dst=f"{ACME_OPERATOR_DIR}/{TLS_LIB_PATH}")
    shutil.copyfile(src=ACME_CLIENT_LIB_PATH, dst=f"{ACME_OPERATOR_DIR}/{ACME_CLIENT_LIB_PATH}")


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    copy_lib_content()
    charm = await ops_test.build_charm("tests/integration/acme-operator")
    await ops_test.model.deploy(
        entity_url=charm,
        resources={"lego-image": METADATA["resources"]["lego-image"]["upstream-source"]},
        application_name=APP_NAME,
        config={
            "email": "example@gmail.com",
            "server": "https://acme-staging-v02.api.letsencrypt.org/directory",
        },
        series="jammy",
    )

    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        raise_on_blocked=True,
        timeout=1000,
    )
    assert ops_test.model.applications[APP_NAME].units[0].workload_status == "active"
