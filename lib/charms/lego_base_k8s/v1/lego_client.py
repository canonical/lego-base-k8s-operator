# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""# lego_client Library.

This library helps user create charms that use LEGO, a letsencrypt client, to provide
certificates to other charms in the charm ecosystem. The certificate requesting functionality
and the distribution of issued certificates are all done by the Charm class that's provided
in this metaclass, which users can inherit to get all of its functionality.

LEGO uses a DNS challenge to verify that users own the domains they are requesting certificates
for. LEGO provides plugins that integrate with online services like Cloudflare directly
to complete this challenge. Users can choose any supported plugin to easily integrate their
ACME provider charms with their preferred domain provider.

Some configuration by the inheriting charm is required.

## Getting Started
To get started using the library, you need to fetch the library using `charmcraft`.
```shell
charmcraft fetch-lib charms.lego_client_operator.v1.lego_client
```

You will also need to fetch the following libraries:

```shell
charmcraft fetch-lib charms.tls_certificates_interface.v4.tls_certificates
charmcraft fetch-lib charms.certificate_transfer_interface.v1.certificate_transfer
charmcraft fetch-lib charms.loki_k8s.v1.loki_push_api
```

You will then need to add the following library to the charm's `requirements.txt` file
alongside the default requirements needed by charms:
- cryptography
- cosl
- pylego

You will need to add the following to your charmcraft.yaml file:
```yaml
config:
  options:
    email:
      type: string
      description: Account email address to receive notifications from Let's Encrypt.
    server:
      type: string
      description: Certificate authority server
      default: "https://acme-v02.api.letsencrypt.org/directory"
    <plugin-name>-config-secret-id:
      type: string
      description: The secret id of the Juju secret that contains all of the configuration
        options required to get a certificate. The secret keys should mirror the environment
        variables required by the plugin in lowercase kebab-case, and the values being
        the values that are required to be provided by the LEGO plugin that will be in use.

        For example, the required variables for Cloudflare is documented in https://go-acme.github.io/lego/dns/cloudflare/index.html
        The format for the secret of a cloudflare plugin should be
        ```
        {
            "cloudflare-email": "your@email.com",
            "cloudflare-api-key": "yourapikey123"
        }
        ```
        A user can create a secret in this format by running
        ```
        juju add-secret plugin-credentials cloudflare-email="your@email.com" cloudflare-api-key="yourapikey123"
        ```

provides:
  certificates:
    interface: tls-certificates
  send-ca-cert:
    interface: certificate_transfer
requires:
  logging:
    interface: loki_push_api

parts:
  charm:
    build-snaps:
      - go
```

Then, to use the library in an example charm, you can do something like the following:
```python
from charms.lego_client_operator.v1.lego_client import AcmeClient
from ops.main import main
class ExampleAcmeCharm(AcmeClient):
    def __init__(self, *args):
        super().__init__(*args, plugin="cloudflare")
        self._server = "https://acme-staging-v02.api.letsencrypt.org/directory"
        self._email = "testingmctestface@test.com"

    def _validate_plugin_config_options(self, plugin_config: Dict[str, str]) -> str:
        if "cloudflare-email" not in plugin_config:
            return "API user was not provided"
        if "cloudflare-api-key" not in plugin_config:
            return "API key was not provided"
        return ""
```

The minimum that Charms such as the above example are expected to do is:
- Inherit from AcmeClient,
- Call `super().__init__(*args, plugin="<plugin-name>")` with the lego plugin name,
  you can look at the list of plugins at https://go-acme.github.io/lego/dns/index.html#dns-providers
- Implement the `_validate_plugin_config_options` method,
  The function should match the signature of the example charm above, and should
  validate the plugin specific configuration. It should return a string with an
  error message if the plugin specific configuration is invalid, which will be
  displayed as the charm's status message, or an empty string if it's valid.
  The charm will attempt to use the plugin_dict information to request a certificate.
  The library itself is responsible for calling this function with the appropriate argument,
  so there is no need to modify or call this function from the top level charm.


Once the charm is deployed, the user requesting a certificate is expected to:
- Pass in an email as a config option
- Optionally pass in an ACME server as config option
- Create a secret that contains all of the required configuration options for the plugin.
- Grant this secret to the charm.
- Pass in the secret id that was generated as a config option.

The user is then free to integrate the charm with any requirer implementing the tls-certificates-interface.
The LEGO charm will simply forward all of the CSR's to the letsencrypt client, and will log any error that may occur.
When a certificate is received, the library will place the resulting certificate and its issuer into the relation
databag as expected of the tls-certificates-interface library.
"""  # noqa: E501

import abc
import logging
import os
import re
from abc import abstractmethod
from contextlib import contextmanager
from typing import Dict
from urllib.parse import urlparse

from charms.certificate_transfer_interface.v1.certificate_transfer import (
    CertificateTransferProvides,
)
from charms.loki_k8s.v1.loki_push_api import LogForwarder
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateSigningRequest,
    ProviderCertificate,
    TLSCertificatesProvidesV4,
)
from ops import ModelError, Secret, SecretNotFoundError
from ops.charm import CharmBase, CollectStatusEvent
from ops.framework import EventBase
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus
from pylego import LEGOError, run_lego_command

# The unique Charmhub library identifier, never change it
LIBID = "d67f92a288e54ab68a6b6349e9b472c4"

# Increment this major API version when introducing breaking changes
LIBAPI = 1

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 0


logger = logging.getLogger(__name__)

CERTIFICATES_RELATION_NAME = "certificates"
CA_TRANSFER_RELATION_NAME = "send-ca-cert"


class AcmeClient(CharmBase):
    """Base charm for charms that use the ACME protocol to get certificates.

    This charm implements the tls_certificates interface as a provider.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, *args, plugin: str):
        super().__init__(*args)
        self._logging = LogForwarder(self, relation_name="logging")
        self.tls_certificates = TLSCertificatesProvidesV4(self, CERTIFICATES_RELATION_NAME)
        self.cert_transfer = CertificateTransferProvides(self, CA_TRANSFER_RELATION_NAME)

        [
            self.framework.observe(event, self._configure)
            for event in [
                self.on[CA_TRANSFER_RELATION_NAME].relation_joined,
                self.on[CERTIFICATES_RELATION_NAME].relation_changed,
                self.on.secret_changed,
                self.on.config_changed,
                self.on.update_status,
            ]
        ]
        self.framework.observe(self.on.collect_unit_status, self._on_collect_status)

        self._plugin = plugin

    def _on_collect_status(self, event: CollectStatusEvent) -> None:
        """Handle the collect status event."""
        if not self.unit.is_leader():
            event.add_status(BlockedStatus("only 1 leader unit can operate at any given time"))
            return
        if err := self._validate_charm_config_options():
            event.add_status(BlockedStatus(err))
            return
        if err := self._validate_plugin_config_options(self._plugin_config):
            event.add_status(BlockedStatus(err))
            return
        event.add_status(ActiveStatus(self._get_certificate_fulfillment_status()))

    def _configure(self, event: EventBase) -> None:
        """Configure the Lego provider."""
        if not self.unit.is_leader():
            logger.error("only the leader unit can handle certificate requests")
            return
        if err := self._validate_charm_config_options():
            logger.error(err)
            return
        if err := self._validate_plugin_config_options(self._plugin_config):
            logger.error(err)
            return
        self._configure_certificates()
        self._configure_ca_certificates()

    def _configure_certificates(self):
        """Attempt to fulfill all certificate requests."""
        certificate_requests = self.tls_certificates.get_certificate_requests()
        provided_certificates = self.tls_certificates.get_provider_certificates()
        certificate_pair_map = {
            csr: list(
                filter(
                    lambda x: x.relation_id == csr.relation_id
                    and x.certificate_signing_request.raw == csr.certificate_signing_request.raw,
                    provided_certificates,
                )
            )
            for csr in certificate_requests
        }
        with self.maintenance_status("processing certificate requests"):
            for certificate_request, assigned_certificates in certificate_pair_map.items():
                if not assigned_certificates:
                    self._generate_signed_certificate(
                        csr=certificate_request.certificate_signing_request,
                        relation_id=certificate_request.relation_id,
                    )

    def _configure_ca_certificates(self):
        """Distribute all used CA certificates to requirers."""
        if len(self.model.relations.get(CA_TRANSFER_RELATION_NAME, [])) > 0:
            self.cert_transfer.add_certificates(
                {
                    str(provider_certificate.ca)
                    for provider_certificate in self.tls_certificates.get_provider_certificates()
                }
            )

    def _generate_signed_certificate(self, csr: CertificateSigningRequest, relation_id: int):
        """Generate signed certificate from the ACME provider."""
        logger.info("generating certificate for domain %s", csr.common_name)
        try:
            response = run_lego_command(
                email=self._email if self._email else "",
                server=self._server if self._server else "",
                csr=csr.raw.encode(),
                env=self._plugin_config | self._app_environment,
                plugin=self._plugin,
            )
        except LEGOError as e:
            logger.error(
                "An error occured executing the lego command: %s. \
                will try again in during the next update status event.",
                e,
            )
            return
        self.tls_certificates.set_relation_certificate(
            provider_certificate=ProviderCertificate(
                certificate=Certificate.from_string(response.certificate),
                certificate_signing_request=CertificateSigningRequest.from_string(response.csr),
                ca=Certificate.from_string(response.issuer_certificate),
                chain=[
                    Certificate.from_string(cert)
                    for cert in [response.certificate, response.issuer_certificate]
                ],
                relation_id=relation_id,
            ),
        )

    def _get_certificate_fulfillment_status(self) -> str:
        """Return the status message reflecting how many certificate requests are still pending."""
        outstanding_requests_num = len(
            self.tls_certificates.get_outstanding_certificate_requests()
        )
        total_requests_num = len(self.tls_certificates.get_certificate_requests())
        fulfilled_certs = total_requests_num - outstanding_requests_num
        message = f"{fulfilled_certs}/{total_requests_num} certificate requests are fulfilled"
        if fulfilled_certs != total_requests_num:
            message += ". please monitor logs for any errors"
        return message

    @abstractmethod
    def _validate_plugin_config_options(self, plugin_config: Dict[str, str]) -> str:
        """Validate plugin specific configuration.

        Implementations need to validate the plugin
        specific configuration that is received as the
        first argument of the function and return either
        an empty string if valid or the error message if invalid.

        Args:
            plugin_config: A dictionary that comes from a juju secret that will
                be passed to the lego runner.

        Returns:
            str: Error message if invalid, otherwise an empty string.
        """
        pass

    def _validate_charm_config_options(self) -> str:
        """Validate generic ACME config.

        Returns:
        str: Error message if invalid, otherwise an empty string.
        """
        if not self._email:
            return "email address was not provided"
        if not self._server:
            return "ACME server was not provided"
        if not self._plugin_config:
            return "plugin configuration secret was not provided"
        if not _email_is_valid(self._email):
            return "invalid email address"
        if not _server_is_valid(self._server):
            return "invalid ACME server"
        return ""

    @contextmanager
    def maintenance_status(self, message: str):
        """Context manager to set the charm status temporarily.

        Useful around long-running operations to indicate that the charm is
        busy.
        """
        previous_status = self.unit.status
        self.unit.status = MaintenanceStatus(message)
        yield
        self.unit.status = previous_status

    @property
    def _app_environment(self) -> Dict[str, str]:
        """Extract proxy model environment variables."""
        env = {}

        if http_proxy := get_env_var(env_var="JUJU_CHARM_HTTP_PROXY"):
            env["HTTP_PROXY"] = http_proxy
        if https_proxy := get_env_var(env_var="JUJU_CHARM_HTTPS_PROXY"):
            env["HTTPS_PROXY"] = https_proxy
        if no_proxy := get_env_var(env_var="JUJU_CHARM_NO_PROXY"):
            env["NO_PROXY"] = no_proxy
        return env

    @property
    def _plugin_config(self) -> Dict[str, str]:
        """Plugin specific additional configuration for the command.

        Will attempt to access the juju secret named <plugin_name>-config-secret-id,
        convert lowercase, kebab-style to uppercase, snake_case, and return all of them
        as a dictionary. Ex:

        namecheap-api-key: "APIKEY1"
        namecheap-api-user: "USER"

        will become

        NAMECHEAP_API_KEY: "APIKEY1"
        NAMECHEAP_API_USER: "USER"

        Returns:
            Dict[str,str]: Plugin specific configuration.
        """
        try:
            plugin_config_secret_id = str(
                self.model.config.get(f"{self._plugin}-config-secret-id", "")
            )
            if not plugin_config_secret_id:
                return {}
            plugin_config_secret: Secret = self.model.get_secret(id=plugin_config_secret_id)
            plugin_config = plugin_config_secret.get_content(refresh=True)
        except (SecretNotFoundError, ModelError):
            return {}
        return {key.upper().replace("-", "_"): value for key, value in plugin_config.items()}

    @property
    def _email(self) -> str | None:
        """Email address to use for the ACME account."""
        email = self.model.config.get("email", None)
        if not isinstance(email, str):
            return None
        return email

    @property
    def _server(self) -> str | None:
        """ACME server address."""
        server = self.model.config.get("server", None)
        if not isinstance(server, str):
            return None
        return server


def get_env_var(env_var: str) -> str | None:
    """Get the environment variable value.

    Looks for all upper-case and all low-case of the `env_var`.

    Args:
        env_var: Name of the environment variable.

    Returns:
        Value of the environment variable. None if not found.
    """
    return os.environ.get(env_var.upper(), os.environ.get(env_var.lower(), None))


def _email_is_valid(email: str) -> bool:
    """Validate the format of the email address."""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False
    return True


def _server_is_valid(server: str) -> bool:
    """Validate the format of the ACME server address."""
    urlparts = urlparse(server)
    if not all([urlparts.scheme, urlparts.netloc]):
        return False
    return True
