# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""# acme_client Library.

This library is designed to enable developers to easily create new charms for the ACME protocol.
This library contains all the logic necessary to get certificates from an ACME server.

## Getting Started
To get started using the library, you need to fetch the library using `charmcraft`.
```shell
charmcraft fetch-lib charms.acme_client_operator.v0.acme_client
```
You will also need to add the following library to the charm's `requirements.txt` file:
- jsonschema
- cryptography

Then, to use the library in an example charm, you can do the following:
```python
from charms.acme_client_operator.v0.acme_client import AcmeClient
from ops.main import main
class ExampleAcmeCharm(AcmeClient):
    def __init__(self, *args):
        super().__init__(*args, plugin="namecheap")
        self._server = "https://acme-staging-v02.api.letsencrypt.org/directory"
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_config_changed(self, _):
        if not self._validate_registrar_config():
            return
        if not self.validate_generic_acme_config():
            return
        self.unit.status = ActiveStatus()

    @property
    def _plugin_config(self):
        return {}
```

Charms using this library are expected to:
- Inherit from AcmeClient
- Call `super().__init__(*args, plugin="")` with the lego plugin name
- Observe `ConfigChanged` to a method called `_on_config_changed`
- `_on_config_changed` must follow those requirements:
  - Validate its specific configuration, blocking if invalid
  - Validate generic configuration, by calling `self.validate_generic_acme_config()`,
    returning immediately when it returns `False`
  - Sets the status to Active
  - Accept any kind of events
- Implement the `_plugin_config` property, returning a dictionary of its specific
  configuration. Keys must be capitalized and follow the plugins documentation from
  lego.

Charms that leverage this library also need to specify a `provides` relation in their
`metadata.yaml` file. For example:
```yaml
provides:
  certificates:
    interface: tls-certificates
```
"""
import abc
import logging
import re
from abc import abstractmethod
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

from charms.tls_certificates_interface.v1.tls_certificates import (  # type: ignore[import]
    CertificateCreationRequestEvent,
    TLSCertificatesProvidesV1,
)
from cryptography import x509
from cryptography.x509.oid import NameOID
from ops.charm import CharmBase
from ops.framework import EventBase
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, WaitingStatus
from ops.pebble import ExecError

# The unique Charmhub library identifier, never change it
LIBID = "b3c9913b68dc42b89dfd0e77ac57236d"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 3

logger = logging.getLogger(__name__)


class AcmeClient(CharmBase):
    """Base charm for charms that use the ACME protocol to get certificates.

    This charm implements the tls_certificates interface as a provider.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, *args, plugin: str):
        super().__init__(*args)
        self._csr_path = "/tmp/csr.pem"
        self._certs_path = "/tmp/.lego/certificates/"
        self._container_name = list(self.meta.containers.values())[0].name
        self._container = self.unit.get_container(self._container_name)
        self.tls_certificates = TLSCertificatesProvidesV1(self, "certificates")
        self.framework.observe(
            self.tls_certificates.on.certificate_creation_request,
            self._on_certificate_creation_request,
        )
        self._plugin = plugin

    def validate_generic_acme_config(self) -> bool:
        """Validates generic ACME config."""
        if not self._email:
            self.unit.status = BlockedStatus("Email address was not provided")
            return False
        if not self._server:
            self.unit.status = BlockedStatus("ACME server was not provided")
            return False
        if not self._email_is_valid(self._email):
            self.unit.status = BlockedStatus("Invalid email address")
            return False
        if not self._server_is_valid(self._server):
            self.unit.status = BlockedStatus("Invalid ACME server")
            return False
        return True

    @abstractmethod
    def _on_config_changed(self, event: EventBase) -> None:
        """Validate configuration and sets status accordingly.

        Implementations need to follow the following steps:

        1. Validate their specific configuration, setting the status
           to `Blocked` if invalid and returning immediately.
        2. Validate generic configuration by calling
           `self.validate_generic_acme_config()`, returning immediately
           if it returns `False`.
        3. Set the status to `Active` and return.

        Args:
            event (EventBase): Any Juju event

        Returns:
            None
        """

    @staticmethod
    def _get_subject_from_csr(certificate_signing_request: str) -> str:
        """Returns subject from a provided CSR."""
        csr = x509.load_pem_x509_csr(certificate_signing_request.encode())
        subject_value = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if isinstance(subject_value, bytes):
            return subject_value.decode()
        else:
            return subject_value

    def _push_csr_to_workload(self, csr: str) -> None:
        """Pushes CSR to workload container."""
        self._container.push(path=self._csr_path, make_dirs=True, source=csr.encode())

    def _execute_lego_cmd(self) -> bool:
        """Executes lego command in workload container."""
        process = self._container.exec(
            self._cmd, timeout=300, working_dir="/tmp", environment=self._plugin_config
        )
        try:
            stdout, error = process.wait_output()
            logger.info(f"Return message: {stdout}, {error}")
        except ExecError as e:
            logger.error("Exited with code %d. Stderr:", e.exit_code)
            for line in e.stderr.splitlines():  # type: ignore
                logger.error("    %s", line)
            return False
        return True

    def _pull_certificates_from_workload(self, csr_subject: str) -> List[Union[bytes, str]]:
        """Pulls certificates from workload container."""
        chain_pem = self._container.pull(path=f"{self._certs_path}{csr_subject}.crt")
        return [cert for cert in chain_pem.read().split("\n\n")]  # type: ignore[arg-type]

    def _on_certificate_creation_request(self, event: CertificateCreationRequestEvent) -> None:
        """Handles certificate creation request event.

        - Retrieves subject from CSR
        - Pushes CSR to workload container
        - Executes lego command in workload
        - Pulls certificates from workload
        - Sends certificates to requesting charm
        """
        self._on_config_changed(event)
        if not isinstance(self.unit.status, ActiveStatus):
            event.defer()
            return
        if not self.unit.is_leader():
            return
        if not self._container.can_connect():
            self.unit.status = WaitingStatus("Waiting for container to be ready")
            event.defer()
            return
        csr_subject = self._get_subject_from_csr(event.certificate_signing_request)
        if len(csr_subject) > 64:
            self.unit.status = BlockedStatus(
                f"Subject is too long (> 64 characters): {csr_subject}"
            )
            return
        logger.info("Received Certificate Creation Request for domain %s", csr_subject)
        self._push_csr_to_workload(event.certificate_signing_request)
        self.unit.status = MaintenanceStatus("Executing lego command")
        if not self._execute_lego_cmd():
            self.unit.status = BlockedStatus(
                "Workload command execution failed, use `juju debug-log` for more information."
            )
            return
        signed_certificates = self._pull_certificates_from_workload(csr_subject)
        self.tls_certificates.set_relation_certificate(
            certificate=signed_certificates[0],
            certificate_signing_request=event.certificate_signing_request,
            ca=signed_certificates[-1],
            chain=list(reversed(signed_certificates)),
            relation_id=event.relation_id,
        )
        self.unit.status = ActiveStatus()

    @property
    def _cmd(self) -> List[str]:
        """Command to run to get the certificate.

        Returns:
            list[str]: Command and args to run.
        """
        if not self._email:
            raise ValueError("Email address was not provided")
        if not self._server:
            raise ValueError("ACME server was not provided")
        return [
            "lego",
            "--email",
            self._email,
            "--accept-tos",
            "--csr",
            self._csr_path,
            "--server",
            self._server,
            "--dns",
            self._plugin,
            "run",
        ]

    @property
    @abstractmethod
    def _plugin_config(self) -> Dict[str, str]:
        """Plugin specific additional configuration for the command.

        Implement this method in your charm to return a dictionary with the plugin specific
        configuration.

        Returns:
            dict[str, str]: Plugin specific configuration.
        """

    @staticmethod
    def _email_is_valid(email: str) -> bool:
        """Validate the format of the email address."""
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return False
        return True

    @staticmethod
    def _server_is_valid(server: str) -> bool:
        """Validate the format of the ACME server address."""
        urlparts = urlparse(server)
        if not all([urlparts.scheme, urlparts.netloc]):
            return False
        return True

    @property
    def _email(self) -> Optional[str]:
        """Email address to use for the ACME account."""
        return self.model.config.get("email", None)

    @property
    def _server(self) -> Optional[str]:
        """ACME server address."""
        return self.model.config.get("server", None)
