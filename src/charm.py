#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.


"""A placeholder charm for the acme_client lib."""

from ops.charm import CharmBase
from ops.main import main


class AcmeClientLibCharm(CharmBase):
    """Placeholder charm for acme_client lib."""

    pass


if __name__ == "__main__":
    main(AcmeClientLibCharm)
