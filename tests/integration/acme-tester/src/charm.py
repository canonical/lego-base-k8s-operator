#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

"""Dummy charm for integration testing."""


import logging

from charms.acme_client_operator.v0.acme_client import AcmeClient  # type: ignore[import]
from ops.main import main

logger = logging.getLogger(__name__)

VALID_LOG_LEVELS = ["info", "debug", "warning", "error", "critical"]


class AcmeTesterCharm(AcmeClient):
    """Dummy charm for integration testing."""

    def __init__(self, *args):
        """Uses the Orc8rBase library to manage events."""
        super().__init__(*args)
        self._server = "https://acme-staging-v02.api.letsencrypt.org/directory"


if __name__ == "__main__":  # pragma: nocover
    main(AcmeTesterCharm)
