#!/usr/bin/env python3
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.


"""A placeholder charm for the lego_client lib."""

from ops.charm import CharmBase
from ops.main import main


class LegoClientLibCharm(CharmBase):
    """Placeholder charm for lego_client lib."""

    pass


if __name__ == "__main__":
    main(LegoClientLibCharm)
