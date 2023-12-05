#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Dummy charm for integration testing."""


from charms.acme_client_operator.v0.acme_client import AcmeClient  # type: ignore[import]
from ops.main import main
from ops.model import ActiveStatus


class AcmeOperator(AcmeClient):
    """Dummy charm for integration testing."""

    def __init__(self, *args):
        """Uses the Orc8rBase library to manage events."""
        super().__init__(*args, plugin="whatever")
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_config_changed(self, _) -> None:
        """Handles config-changed events."""
        if not self.validate_generic_acme_config():
            return
        self.unit.status = ActiveStatus()

    def _plugin_config(self) -> dict:
        """Plugin specific additional configuration for the command."""
        return {}


if __name__ == "__main__":  # pragma: nocover
    main(AcmeOperator)
