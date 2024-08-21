# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml
from charms.lego_base_k8s.v1.lego_client import AcmeClient
from charms.tls_certificates_interface.v4.tls_certificates import (
    ProviderCertificate,
    RequirerCSR,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops import testing
from ops.model import ActiveStatus, BlockedStatus
from ops.testing import Harness
from pylego import LEGOError, LEGOResponse
from pylego.pylego import Metadata

testing.SIMULATE_CAN_CONNECT = True  # type: ignore[attr-defined]
test_cert = Path(__file__).parent / "test_lego.crt"
TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"
CERT_TRANSFER_LIB_PATH = "charms.certificate_transfer_interface.v1.certificate_transfer"
CERTIFICATES_RELATION_NAME = "certificates"
CA_TRANSFER_RELATION_NAME = "send-ca-cert"


class AcmeTestCharm(AcmeClient):
    def __init__(self, *args):
        """Use the AcmeClient library to manage events."""
        super().__init__(*args, plugin="example")
        self.valid_config = True

    def _validate_plugin_config_options(self, plugin_config: dict[str, str]) -> str:
        if not self.valid_config:
            return "invalid plugin configuration"
        return ""


class TestCharmV1(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(
            AcmeTestCharm,
            meta=yaml.safe_dump(
                {
                    "name": "lego",
                    "provides": {
                        CERTIFICATES_RELATION_NAME: {"interface": "tls-certificates"},
                        CA_TRANSFER_RELATION_NAME: {"interface": "tls-certificate-transfer"},
                    },
                    "requires": {"logging": {"interface": "loki-push-api"}},
                }
            ),
            config=yaml.safe_dump(
                {
                    "options": {
                        "email": {
                            "description": "lego-image",
                            "type": "string",
                        },
                        "server": {
                            "description": "lego-image",
                            "type": "string",
                        },
                        "example-config-secret-id": {
                            "description": "lego-image",
                            "type": "string",
                        },
                    }
                }
            ),
        )
        self.harness.set_leader()
        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def create_and_grant_plugin_config_secret(self, content: dict[str, str]):
        id = self.harness.add_user_secret(content)
        self.harness.grant_secret(id, self.harness.charm.app.name)
        return id

    def test_given_not_leader_when_update_status_then_status_is_blocked(self):
        self.harness.set_leader(False)
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
            "this charm does not scale, only the leader unit manages certificates."
        )

    def test_given_email_address_not_provided_when_update_config_then_status_is_blocked(self):
        self.harness.update_config(
            {
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus("email address was not provided")

    def test_given_server_not_provided_when_update_config_then_status_is_blocked(self):
        self.harness.update_config(
            {
                "email": "banana@gmail.com",
            }
        )
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus("ACME server was not provided")

    def test_given_secret_id_not_provided_when_update_config_then_status_is_blocked(self):
        self.harness.update_config(
            {
                "email": "banana@gmail.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus(
            "plugin configuration secret was not provided"
        )

    def test_given_invalid_email_when_update_config_then_status_is_blocked(self):
        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "invalid email",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus("invalid email address")

    def test_given_invalid_server_when_update_config_then_status_is_blocked(self):
        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "example@email.com",
                "server": "Invalid ACME server",
                "example-config-secret-id": id,
            }
        )
        self.harness.evaluate_status()
        assert self.harness.model.unit.status == BlockedStatus("invalid ACME server")

    def test_given_invalid_plugin_config_when_update_status_then_status_is_blocked(self):
        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )
        relation_id = self.harness.add_relation(CERTIFICATES_RELATION_NAME, "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.charm.valid_config = False

        self.harness.evaluate_status()

        assert self.harness.charm.unit.status == BlockedStatus("invalid plugin configuration")

    def test_given_valid_specific_config_when_update_status_then_status_is_active(self):
        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )
        relation_id = self.harness.add_relation(CERTIFICATES_RELATION_NAME, "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")

        self.harness.evaluate_status()

        assert self.harness.charm.unit.status == ActiveStatus(
            "0/0 certificate requests are fulfilled"
        )

    @patch("charms.lego_base_k8s.v1.lego_client.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate", new=Mock)
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_provider_certificates")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_valid_config_and_pending_requests_when_update_status_then_status_is_active(
        self, mock_get_certificate_requests, mock_get_provider_certificates, mock_pylego
    ):
        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )
        relation_id = self.harness.add_relation(CERTIFICATES_RELATION_NAME, "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")

        csr_pk_1 = generate_private_key()
        csr_1 = generate_csr(csr_pk_1, "foo.com")

        csr_pk_2 = generate_private_key()
        csr_2 = generate_csr(csr_pk_2, "bar.com")

        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=365)
        cert = generate_certificate(csr_1, issuer, issuer_pk, 365)
        chain = [cert, issuer]

        mock_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                certificate_signing_request=csr_1,
            ),
            RequirerCSR(
                relation_id=relation_id,
                certificate_signing_request=csr_2,
            ),
        ]
        mock_get_provider_certificates.return_value = [
            ProviderCertificate(
                relation_id=relation_id,
                certificate_signing_request=csr_1,
                ca=issuer,
                certificate=cert,
                chain=chain,
            )
        ]

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status,
            ActiveStatus(
                "1/2 certificate requests are fulfilled. please monitor logs for any errors"
            ),
        )

    @patch("charms.lego_base_k8s.v1.lego_client.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    def test_given_cmd_when_certificate_creation_request_then_certificate_is_set_in_relation(
        self, mock_set_relation_certificate, mock_get_outstanding_certificate_requests, mock_pylego
    ):
        relation_id = self.harness.add_relation(CERTIFICATES_RELATION_NAME, "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")

        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")
        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=365)
        cert = generate_certificate(csr, issuer, issuer_pk, validity=365)
        chain = [cert, issuer]

        mock_get_outstanding_certificate_requests.return_value = [
            RequirerCSR(relation_id=relation_id, certificate_signing_request=csr)
        ]

        mock_pylego.return_value = LEGOResponse(
            csr=str(csr),
            private_key=str(generate_private_key()),
            certificate=str(cert),
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable url", url="url", domain="domain.com"),
        )

        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )

        mock_set_relation_certificate.assert_called_with(
            provider_certificate=ProviderCertificate(
                certificate=cert,
                certificate_signing_request=csr,
                ca=issuer,
                chain=chain,
                relation_id=relation_id,
            ),
        )

    @patch("charms.lego_base_k8s.v1.lego_client.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    def test_given_cmd_execution_fails_when_certificate_creation_request_then_request_fails(
        self, mock_set_relation_certificate, mock_get_certificate_requests, mock_pylego
    ):
        relation_id = self.harness.add_relation(CERTIFICATES_RELATION_NAME, "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")

        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")

        mock_get_certificate_requests.return_value = [
            RequirerCSR(relation_id=relation_id, certificate_signing_request=csr)
        ]

        mock_pylego.side_effect = LEGOError("its bad")

        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )

        assert not mock_set_relation_certificate.called

    @patch.dict(
        "os.environ",
        {
            "JUJU_CHARM_HTTP_PROXY": "Random proxy",
            "JUJU_CHARM_HTTPS_PROXY": "Random https proxy",
            "JUJU_CHARM_NO_PROXY": "No proxy",
        },
    )
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate", new=Mock)
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch("charms.lego_base_k8s.v1.lego_client.run_lego_command")
    def test_given_cmd_when_app_environment_variables_set_then_command_executed_with_environment_variables(  # noqa: E501
        self,
        mock_pylego,
        mock_get_certificate_requests,
    ):
        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )

        relation_id = self.harness.add_relation(CERTIFICATES_RELATION_NAME, "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")

        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")
        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=365)
        cert = generate_certificate(csr, issuer, issuer_pk, 365)

        mock_get_certificate_requests.return_value = [
            RequirerCSR(
                relation_id=relation_id,
                certificate_signing_request=csr,
            )
        ]

        mock_pylego.return_value = LEGOResponse(
            csr=str(csr),
            private_key=str(generate_private_key()),
            certificate=str(cert),
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable url", url="url", domain="domain.com"),
        )

        self.harness.charm.on.update_status.emit()

        mock_pylego.assert_called_with(
            email="banana@email.com",
            server="https://acme-v02.api.letsencrypt.org/directory",
            csr=str(csr).encode(),
            env={
                "API_KEY": "key",
                "HTTP_PROXY": "Random proxy",
                "HTTPS_PROXY": "Random https proxy",
                "NO_PROXY": "No proxy",
            },
            plugin="example",
        )

    @patch(f"{CERT_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    def test_given_cert_transfer_relation_not_created_then_ca_certificates_not_added_in_relation_data(  # noqa: E501
        self, mock_add_certificates
    ):
        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )

        self.harness.charm.on.config_changed.emit()
        mock_add_certificates.assert_not_called()

    @patch(f"{CERT_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_provider_certificates")
    def test_given_cert_transfer_relation_and_ca_certificates_then_ca_certificates_added_in_relation_data(  # noqa: E501
        self, mock_get_provider_certificates, mock_add_certificates
    ):
        private_key = generate_private_key()
        csr = generate_csr(private_key, "foo.com")

        server_private_key = generate_private_key()
        ca = generate_ca(server_private_key, 365, "ca.com")
        certificate = generate_certificate(csr, ca, server_private_key, 365)

        mock_get_provider_certificates.return_value = [
            ProviderCertificate(
                relation_id=0,
                certificate_signing_request=csr,
                certificate=certificate,
                ca=ca,
                chain=[ca],
                revoked=False,
            )
        ]

        id = self.create_and_grant_plugin_config_secret(content={"api-key": "key"})
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": id,
            }
        )

        self.harness.add_relation(CA_TRANSFER_RELATION_NAME, "remote")

        self.harness.charm.on.config_changed.emit()

        mock_add_certificates.assert_called_with({str(ca)})
