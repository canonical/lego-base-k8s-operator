# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from charms.lego_base_k8s.v1.lego_client import AcmeClient
from charms.tls_certificates_interface.v4.tls_certificates import (
    ProviderCertificate,
    RequirerCertificateRequest,
    generate_ca,
    generate_certificate,
    generate_csr,
    generate_private_key,
)
from ops.model import ActiveStatus, BlockedStatus
from pylego import LEGOError, LEGOResponse
from pylego.pylego import Metadata
from scenario import Context, Relation, Secret, State

TLS_LIB_PATH = "charms.tls_certificates_interface.v4.tls_certificates"
CERT_TRANSFER_LIB_PATH = "charms.certificate_transfer_interface.v1.certificate_transfer"
CERTIFICATES_RELATION_NAME = "certificates"
CA_TRANSFER_RELATION_NAME = "send-ca-cert"


class AcmeTestCharm(AcmeClient):
    def __init__(self, *args: Any):
        """Use the AcmeClient library to manage events."""
        super().__init__(*args, plugin="example")

    def _validate_plugin_config_options(self, plugin_config: dict[str, str]) -> str:
        if "API_KEY" not in plugin_config:
            return "invalid plugin configuration"
        return ""


class TestCharmV1:
    @pytest.fixture(scope="function", autouse=True)
    def context(self):
        self.ctx = Context(
            charm_type=AcmeTestCharm,
            meta={
                "name": "lego",
                "provides": {
                    CERTIFICATES_RELATION_NAME: {"interface": "tls-certificates"},
                    CA_TRANSFER_RELATION_NAME: {"interface": "tls-certificate-transfer"},
                },
                "requires": {"logging": {"interface": "loki-push-api"}},
            },
            config={
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
            },
        )

    def test_given_not_leader_when_update_status_then_status_is_blocked(self):
        state = State(leader=False)
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == BlockedStatus(
            "this charm does not scale, only the leader unit manages certificates."
        )

    def test_given_email_address_not_provided_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            config={
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            },
        )
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == BlockedStatus("email address was not provided")

    def test_given_server_not_provided_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            config={
                "email": "banana@gmail.com",
            },
        )
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == BlockedStatus("ACME server was not provided")

    def test_given_secret_id_not_provided_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            config={
                "email": "banana@gmail.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            },
        )
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == BlockedStatus("plugin configuration secret was not provided")

    def test_given_invalid_email_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "invalid email",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
        )
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == BlockedStatus("invalid email address")

    def test_given_invalid_server_when_update_config_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "Invalid ACME server",
                "example-config-secret-id": "1",
            },
        )
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == BlockedStatus("invalid ACME server")

    def test_given_invalid_plugin_config_when_update_status_then_status_is_blocked(self):
        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"wrong-api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
            relations=[Relation(endpoint=CERTIFICATES_RELATION_NAME)],
        )
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == BlockedStatus("invalid plugin configuration")

    def test_given_valid_specific_config_when_update_status_then_status_is_active(self):
        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
            relations=[Relation(endpoint=CERTIFICATES_RELATION_NAME)],
        )
        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == ActiveStatus("0/0 certificate requests are fulfilled")

    @patch("charms.lego_base_k8s.v1.lego_client.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate", new=Mock)
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_provider_certificates")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    def test_given_valid_config_and_pending_requests_when_update_status_then_status_is_active(
        self,
        mock_get_certificate_requests: MagicMock,
        mock_get_provider_certificates: MagicMock,
        mock_pylego: MagicMock,
    ):
        csr_pk_1 = generate_private_key()
        csr_1 = generate_csr(csr_pk_1, "foo.com")

        csr_pk_2 = generate_private_key()
        csr_2 = generate_csr(csr_pk_2, "bar.com")

        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=timedelta(days=365))
        cert = generate_certificate(csr_1, issuer, issuer_pk, timedelta(days=365))
        chain = [cert, issuer]

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(
                relation_id=1,
                certificate_signing_request=csr_1,
                is_ca=False,
            ),
            RequirerCertificateRequest(
                relation_id=1,
                certificate_signing_request=csr_2,
                is_ca=False,
            ),
        ]
        mock_get_provider_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                certificate_signing_request=csr_1,
                ca=issuer,
                certificate=cert,
                chain=chain,
            )
        ]

        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
            relations=[
                Relation(relation_id=1, endpoint=CERTIFICATES_RELATION_NAME),
            ],
        )

        out = self.ctx.run("collect-unit-status", state)
        assert out.unit_status == ActiveStatus(
            "1/2 certificate requests are fulfilled. please monitor logs for any errors"
        )

    @patch("charms.lego_base_k8s.v1.lego_client.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    def test_given_cmd_when_certificate_creation_request_then_certificate_is_set_in_relation(
        self,
        mock_set_relation_certificate: MagicMock,
        mock_get_outstanding_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")
        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=timedelta(days=365))
        cert = generate_certificate(csr, issuer, issuer_pk, validity=timedelta(days=365))
        chain = [cert, issuer]

        mock_get_outstanding_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=False)
        ]

        mock_pylego.return_value = LEGOResponse(
            csr=str(csr),
            private_key=str(generate_private_key()),
            certificate=str(cert),
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable url", url="url", domain="domain.com"),
        )

        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
            relations=[
                Relation(relation_id=1, endpoint=CERTIFICATES_RELATION_NAME),
            ],
        )

        self.ctx.run("update-status", state)
        mock_set_relation_certificate.assert_called_with(
            provider_certificate=ProviderCertificate(
                certificate=cert,
                certificate_signing_request=csr,
                ca=issuer,
                chain=chain,
                relation_id=1,
            ),
        )

    @patch("charms.lego_base_k8s.v1.lego_client.run_lego_command")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_certificate_requests")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.set_relation_certificate")
    def test_given_cmd_execution_fails_when_certificate_creation_request_then_request_fails(
        self,
        mock_set_relation_certificate: MagicMock,
        mock_get_certificate_requests: MagicMock,
        mock_pylego: MagicMock,
    ):
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(relation_id=1, certificate_signing_request=csr, is_ca=False)
        ]

        mock_pylego.side_effect = LEGOError("its bad")

        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
            relations=[
                Relation(relation_id=1, endpoint=CERTIFICATES_RELATION_NAME),
            ],
        )

        self.ctx.run("update-status", state)
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
        mock_pylego: MagicMock,
        mock_get_certificate_requests: MagicMock,
    ):
        csr_pk = generate_private_key()
        csr = generate_csr(csr_pk, "foo.com")
        issuer_pk = generate_private_key()
        issuer = generate_ca(issuer_pk, common_name="ca", validity=timedelta(days=365))
        cert = generate_certificate(csr, issuer, issuer_pk, timedelta(days=365))

        mock_get_certificate_requests.return_value = [
            RequirerCertificateRequest(
                relation_id=1,
                certificate_signing_request=csr,
                is_ca=False,
            )
        ]

        mock_pylego.return_value = LEGOResponse(
            csr=str(csr),
            private_key=str(generate_private_key()),
            certificate=str(cert),
            issuer_certificate=str(issuer),
            metadata=Metadata(stable_url="stable url", url="url", domain="domain.com"),
        )

        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
            relations=[
                Relation(relation_id=1, endpoint=CERTIFICATES_RELATION_NAME),
            ],
        )

        self.ctx.run("update-status", state)

        mock_pylego.assert_called_with(
            email="example@email.com",
            server="https://acme-v02.api.letsencrypt.org/directory",
            csr=str(csr).encode(),
            env={
                "API_KEY": "apikey123",
                "HTTP_PROXY": "Random proxy",
                "HTTPS_PROXY": "Random https proxy",
                "NO_PROXY": "No proxy",
            },
            plugin="example",
        )

    @patch(f"{CERT_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    def test_given_cert_transfer_relation_not_created_then_ca_certificates_not_added_in_relation_data(  # noqa: E501
        self, mock_add_certificates: MagicMock
    ):
        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
            relations=[
                Relation(relation_id=1, endpoint=CERTIFICATES_RELATION_NAME),
            ],
        )

        self.ctx.run("update-status", state)
        mock_add_certificates.assert_not_called()

    @patch(f"{CERT_TRANSFER_LIB_PATH}.CertificateTransferProvides.add_certificates")
    @patch(f"{TLS_LIB_PATH}.TLSCertificatesProvidesV4.get_provider_certificates")
    def test_given_cert_transfer_relation_and_ca_certificates_then_ca_certificates_added_in_relation_data(  # noqa: E501
        self, mock_get_provider_certificates: MagicMock, mock_add_certificates: MagicMock
    ):
        private_key = generate_private_key()
        csr = generate_csr(private_key, "foo.com")

        server_private_key = generate_private_key()
        ca = generate_ca(server_private_key, timedelta(days=365), "ca.com")
        certificate = generate_certificate(csr, ca, server_private_key, timedelta(days=365))

        mock_get_provider_certificates.return_value = [
            ProviderCertificate(
                relation_id=1,
                certificate_signing_request=csr,
                certificate=certificate,
                ca=ca,
                chain=[ca],
                revoked=False,
            )
        ]

        state = State(
            leader=True,
            secrets=[Secret(id="1", contents={0: {"api-key": "apikey123"}})],
            config={
                "email": "example@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
                "example-config-secret-id": "1",
            },
            relations=[
                Relation(relation_id=1, endpoint=CERTIFICATES_RELATION_NAME),
                Relation(relation_id=2, endpoint=CA_TRANSFER_RELATION_NAME),
            ],
        )

        self.ctx.run("update-status", state)

        mock_add_certificates.assert_called_with({str(ca)})
