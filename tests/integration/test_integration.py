#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.


import logging
import shutil
from pathlib import Path

import pytest
import yaml

logger = logging.getLogger(__name__)

METADATA = yaml.safe_load(Path("tests/integration/lego-operator/metadata.yaml").read_text())
APP_NAME = METADATA["name"]
TLS_LIB_PATH = "lib/charms/tls_certificates_interface/v3/tls_certificates.py"
LOKI_LIB_PATH = "lib/charms/loki_k8s/v1/loki_push_api.py"
LEGO_CLIENT_LIB_PATH = "lib/charms/lego_base_k8s/v0/lego_client.py"
LEGO_OPERATOR_DIR = "tests/integration/lego-operator"
GRAFANA_AGENT_CHARM_NAME = "grafana-agent-k8s"


def copy_lib_content() -> None:
    shutil.copyfile(src=TLS_LIB_PATH, dst=f"{LEGO_OPERATOR_DIR}/{TLS_LIB_PATH}")
    shutil.copyfile(src=LOKI_LIB_PATH, dst=f"{LEGO_OPERATOR_DIR}/{LOKI_LIB_PATH}")
    shutil.copyfile(src=LEGO_CLIENT_LIB_PATH, dst=f"{LEGO_OPERATOR_DIR}/{LEGO_CLIENT_LIB_PATH}")


@pytest.mark.abort_on_fail
async def test_build_and_deploy(ops_test):
    """Build the charm-under-test and deploy it together with related charms.

    Assert on the unit status before any relations/configurations take place.
    """
    copy_lib_content()
    charm = await ops_test.build_charm("tests/integration/lego-operator")
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


@pytest.mark.abort_on_fail
async def test_given_grafana_agent_when_integrate_then_status_is_active(ops_test):
    """Integrate with a logging endpoint."""
    await ops_test.model.deploy(
        GRAFANA_AGENT_CHARM_NAME,
        application_name=GRAFANA_AGENT_CHARM_NAME,
        channel="stable",
    )
    await ops_test.model.integrate(
        relation1=f"{APP_NAME}:logging", relation2=GRAFANA_AGENT_CHARM_NAME
    )
    await ops_test.model.wait_for_idle(
        apps=[APP_NAME],
        status="active",
        timeout=1000,
    )
