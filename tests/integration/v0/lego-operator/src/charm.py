#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Dummy charm for integration testing."""

from typing import Any, Dict

from charms.lego_base_k8s.v0.lego_client import AcmeClient
from ops.main import main


class LegoOperator(AcmeClient):
    """Dummy charm for integration testing."""

    def __init__(self, *args: Any):
        """Use the Orc8rBase library to manage events."""
        super().__init__(*args, plugin="whatever")

    def _validate_plugin_config(self) -> str:
        """Validate the plugin specific configuration."""
        return ""

    @property
    def _plugin_config(self) -> Dict[str, str]:
        """Plugin specific additional configuration for the command."""
        return {"key": "value"}


if __name__ == "__main__":  # pragma: nocover
    main(LegoOperator)
