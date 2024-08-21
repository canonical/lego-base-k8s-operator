#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Dummy charm for integration testing."""

from charms.lego_base_k8s.v1.lego_client import AcmeClient
from ops.main import main


class LegoOperator(AcmeClient):
    """Dummy charm for integration testing."""

    def __init__(self, *args):
        super().__init__(*args, plugin="test")

    def _validate_plugin_config_options(self, plugin_config: dict[str, str]) -> str:
        """Validate the plugin specific configuration."""
        return ""


if __name__ == "__main__":  # pragma: nocover
    main(LegoOperator)
