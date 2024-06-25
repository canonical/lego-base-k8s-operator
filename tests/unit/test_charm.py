# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.
#
# Learn more about testing at: https://juju.is/docs/sdk/testing
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml
from charms.lego_base_k8s.v0.lego_client import AcmeClient
from charms.tls_certificates_interface.v3.tls_certificates import (
    generate_csr,
    generate_private_key,
)
from ops import testing
from ops.model import ActiveStatus, BlockedStatus, WaitingStatus
from ops.pebble import ExecError
from ops.testing import Harness

testing.SIMULATE_CAN_CONNECT = True  # type: ignore[attr-defined]
test_cert = Path(__file__).parent / "test_lego.crt"
TLS_LIB_PATH = "charms.tls_certificates_interface.v3.tls_certificates"


class MockExec:
    def __init__(self, *args, **kwargs):
        if "raise_exec_error" in kwargs:
            self.raise_exec_error = True
        else:
            self.raise_exec_error = False

    def wait_output(self, *args, **kwargs):
        if self.raise_exec_error:
            raise ExecError(command=["lego"], exit_code=1, stdout="", stderr="")
        return "stdout", "stderr"


class AcmeTestCharm(AcmeClient):
    def __init__(self, *args):
        """Use the AcmeClient library to manage events."""
        super().__init__(*args, plugin="namecheap")
        self.valid_config = True

    def _validate_plugin_config(self):
        if not self.valid_config:
            return "Invalid specific configuration"
        return ""

    @property
    def _plugin_config(self):
        return {}


class TestCharm(unittest.TestCase):
    def setUp(self):
        self.harness = Harness(
            AcmeTestCharm,
            meta=yaml.safe_dump(
                {
                    "name": "lego",
                    "containers": {"lego": {"resource": "lego-image"}},
                    "provides": {"certificates": {"interface": "tls-certificates"}},
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
                    }
                }
            ),
        )

        self.addCleanup(self.harness.cleanup)
        self.harness.begin()

    def add_csr_to_remote_unit_relation_data(
        self, relation_id: int, app_or_unit: str, subject: str = "foo"
    ) -> str:
        """Add a CSR to the remote unit relation data.

        Returns: The CSR as a string.
        """
        csr = generate_csr(generate_private_key(), subject=subject)
        self.harness.update_relation_data(
            relation_id=relation_id,
            app_or_unit=app_or_unit,
            key_values={
                "certificate_signing_requests": json.dumps(
                    [{"certificate_signing_request": csr.decode().strip()}]
                )
            },
        )
        return csr.decode().strip()

    def test_given_email_address_not_provided_when_update_config_then_status_is_blocked(
        self,
    ):
        self.harness.set_can_connect("lego", True)
        self.harness.update_config(
            {
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        return_value = self.harness.charm.validate_generic_acme_config()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("Email address was not provided")
        )
        self.assertEqual(return_value, "Email address was not provided")

    def test_given_server_not_provided_when_update_config_then_status_is_blocked(
        self,
    ):
        self.harness.set_can_connect("lego", True)
        self.harness.update_config(
            {
                "email": "banana@gmail.com",
            }
        )
        return_value = self.harness.charm.validate_generic_acme_config()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status, BlockedStatus("ACME server was not provided")
        )
        self.assertEqual(return_value, "ACME server was not provided")

    def test_given_invalid_email_when_update_config_then_status_is_blocked(self):
        self.harness.set_can_connect("lego", True)
        self.harness.update_config(
            {
                "email": "invalid email",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        return_value = self.harness.charm.validate_generic_acme_config()

        self.harness.evaluate_status()

        self.assertEqual(self.harness.model.unit.status, BlockedStatus("Invalid email address"))
        self.assertEqual(return_value, "Invalid email address")

    def test_given_invalid_server_when_update_config_then_status_is_blocked(self):
        self.harness.set_can_connect("lego", True)
        self.harness.update_config(
            {
                "email": "example@email.com",
                "server": "Invalid ACME server",
            }
        )

        return_value = self.harness.charm.validate_generic_acme_config()

        self.harness.evaluate_status()

        self.assertEqual(self.harness.model.unit.status, BlockedStatus("Invalid ACME server"))
        self.assertEqual(return_value, "Invalid ACME server")

    @patch("ops.model.Container.exec", new=MockExec)
    @patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate",
    )
    def test_given_cmd_when_certificate_creation_request_then_certificate_is_set_in_relation(
        self, mock_set_relation_certificate
    ):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        container = self.harness.model.unit.get_container("lego")
        container.push(
            "/tmp/.lego/certificates/foo.crt", source=test_cert.read_bytes(), make_dirs=True
        )

        csr = self.add_csr_to_remote_unit_relation_data(
            relation_id=relation_id, app_or_unit="remote/0"
        )

        with open(test_cert, "r") as file:
            expected_certs = (file.read()).split("\n\n")
        mock_set_relation_certificate.assert_called_with(
            certificate=expected_certs[0],
            certificate_signing_request=csr,
            ca=expected_certs[-1],
            chain=list(reversed(expected_certs)),
            relation_id=relation_id,
        )

    @patch("ops.model.Container.exec", new_callable=Mock)
    def test_given_command_execution_fails_when_certificate_creation_request_then_request_fails(  # noqa: E501
        self, patch_exec
    ):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        patch_exec.return_value = MockExec(raise_exec_error=True)
        container = self.harness.model.unit.get_container("lego")
        container.push(
            "/tmp/.lego/certificates/foo.crt", source=test_cert.read_bytes(), make_dirs=True
        )

        with self.assertLogs(level="ERROR") as log:
            self.add_csr_to_remote_unit_relation_data(
                relation_id=relation_id, app_or_unit="remote/0"
            )
            self.assertIn(
                "Failed to execute lego command",
                log.output[1],
            )

    def test_given_cannot_connect_to_container_when_certificate_creation_request_then_status_is_waiting(  # noqa: E501
        self,
    ):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", False)

        self.add_csr_to_remote_unit_relation_data(
                relation_id=relation_id, app_or_unit="remote/0"
            )

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.model.unit.status,
            WaitingStatus("Waiting to be able to connect to LEGO container"),
        )

    def test_given_subject_name_is_too_long_when_certificate_creation_request_then_message_is_logged(  # noqa: E501
        self,
    ):
        long_subject_names = ["a" * 65, "a" * 66, "a" * 255]
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)

        for long_subject_name in long_subject_names:
            self.add_csr_to_remote_unit_relation_data(
                relation_id=relation_id, app_or_unit="remote/0", subject=long_subject_name
            )

            with self.assertLogs(level="ERROR") as log:
                self.add_csr_to_remote_unit_relation_data(
                    relation_id=relation_id, app_or_unit="remote/0", subject=long_subject_name
                )
                self.assertIn(
                    f"Subject is too long (> 64 characters): {long_subject_name}", log.output[0]
                )

    def test_given_generic_config_is_not_valid_when_certificate_creation_request_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.update_config(
            {
                "email": "banana",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)

        self.add_csr_to_remote_unit_relation_data(relation_id=relation_id, app_or_unit="remote/0")

        self.harness.evaluate_status()

        assert self.harness.charm.unit.status == BlockedStatus("Invalid email address")

    @patch("ops.model.Container.exec", new=MockExec)
    @patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate",
    )
    def test_given_valid_config_and_pending_requests_when_update_status_then_status_is_active(  # noqa: E501
        self, mock_set_relation_certificate
    ):
        self.harness.set_leader(False)
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        self.harness.charm.valid_config = True
        container = self.harness.model.unit.get_container("lego")
        container.push(
            "/tmp/.lego/certificates/foo.crt", source=test_cert.read_bytes(), make_dirs=True
        )

        self.add_csr_to_remote_unit_relation_data(relation_id=relation_id, app_or_unit="remote/0")

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status, ActiveStatus(
                "0/1 certificate requests are fulfilled"
            )
        )

    def test_given_generic_config_is_not_valid_when_update_status_then_status_is_blocked(
        self,
    ):
        self.harness.update_config(
            {
                "email": "banana",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)

        self.harness.charm.on.update_status.emit()

        self.harness.evaluate_status()

        assert self.harness.charm.unit.status == BlockedStatus("Invalid email address")

    def test_given_generic_config_is_not_valid_when_config_changed_then_status_is_blocked(
        self,
    ):
        self.harness.update_config(
            {
                "email": "banana",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)

        self.harness.charm.on.config_changed.emit()

        self.harness.evaluate_status()

        assert self.harness.charm.unit.status == BlockedStatus("Invalid email address")

    def test_given_invalid_specific_config_when_update_status_then_status_is_blocked(self):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        self.harness.charm.valid_config = False

        self.harness.charm.on.update_status.emit()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status, BlockedStatus("Invalid specific configuration")
        )

    def test_given_invalid_specific_config_when_config_changed_then_status_is_blocked(self):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        self.harness.charm.valid_config = False

        self.harness.charm.on.config_changed.emit()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status, BlockedStatus("Invalid specific configuration")
        )

    def test_given_invalid_specific_config_when_certificate_creation_request_then_status_is_blocked(  # noqa: E501
        self,
    ):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        self.harness.charm.valid_config = False

        self.harness.charm.on.config_changed.emit()

        self.harness.evaluate_status()

        self.assertEqual(
            self.harness.charm.unit.status, BlockedStatus("Invalid specific configuration")
        )

    @patch("ops.model.Container.exec", new=MockExec)
    @patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate",
    )
    def test_given_cmd_and_outstanding_requests_when_update_status_then_certificate_is_set_in_relation(  # noqa: E501
        self, mock_set_relation_certificate
    ):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(False)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        container = self.harness.model.unit.get_container("lego")
        container.push(
            "/tmp/.lego/certificates/foo.crt", source=test_cert.read_bytes(), make_dirs=True
        )

        csr = self.add_csr_to_remote_unit_relation_data(
            relation_id=relation_id, app_or_unit="remote/0"
        )

        mock_set_relation_certificate.assert_not_called()

        self.harness.set_leader(True)
        self.harness.charm.on.update_status.emit()

        with open(test_cert, "r") as file:
            expected_certs = (file.read()).split("\n\n")
        mock_set_relation_certificate.assert_called_with(
            certificate=expected_certs[0],
            certificate_signing_request=csr,
            ca=expected_certs[-1],
            chain=list(reversed(expected_certs)),
            relation_id=relation_id,
        )

    @patch("ops.model.Container.exec", new=MockExec)
    @patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate",
    )
    def test_given_cmd_and_outstanding_requests_when_config_changed_then_certificate_is_set_in_relation(  # noqa: E501
        self, mock_set_relation_certificate
    ):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        self.harness.set_leader(False)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        container = self.harness.model.unit.get_container("lego")
        container.push(
            "/tmp/.lego/certificates/foo.crt", source=test_cert.read_bytes(), make_dirs=True
        )

        csr = self.add_csr_to_remote_unit_relation_data(
            relation_id=relation_id, app_or_unit="remote/0"
        )

        mock_set_relation_certificate.assert_not_called()

        self.harness.set_leader(True)
        self.harness.charm.on.config_changed.emit()

        with open(test_cert, "r") as file:
            expected_certs = (file.read()).split("\n\n")
        mock_set_relation_certificate.assert_called_with(
            certificate=expected_certs[0],
            certificate_signing_request=csr,
            ca=expected_certs[-1],
            chain=list(reversed(expected_certs)),
            relation_id=relation_id,
        )

    @patch("ops.model.Container.exec")
    @patch.dict(
        "os.environ", {
            "HTTP_PROXY": "Random proxy",
            "HTTPS_PROXY": "Random https proxy",
            "NO_PROXY": "No proxy",
        }
    )
    @patch(
        f"{TLS_LIB_PATH}.TLSCertificatesProvidesV3.set_relation_certificate",
    )
    def test_given_cmd_when_app_environment_variables_set_then_command_executed_with_environment_variables(  # noqa: E501
        self,
        _,
        mock_exec,
    ):
        self.harness.update_config(
            {
                "email": "banana@email.com",
                "server": "https://acme-v02.api.letsencrypt.org/directory",
            }
        )
        mock_exec.return_value =  MockExec()
        self.harness.set_leader(True)
        relation_id = self.harness.add_relation("certificates", "remote")
        self.harness.add_relation_unit(relation_id, "remote/0")
        self.harness.set_can_connect("lego", True)
        container = self.harness.model.unit.get_container("lego")
        container.push(
            "/tmp/.lego/certificates/foo.crt", source=test_cert.read_bytes(), make_dirs=True
        )
        self.add_csr_to_remote_unit_relation_data(
            relation_id=relation_id, app_or_unit="remote/0"
        )
        mock_exec.assert_called_with(
            [
                'lego',
                '--email',
                'banana@email.com',
                '--accept-tos',
                '--csr', '/tmp/csr.pem',
                '--server', 'https://acme-v02.api.letsencrypt.org/directory',
                '--dns', 'namecheap',
                'run'
            ],
            timeout=300,
            working_dir="/tmp",
            environment={
            "HTTP_PROXY": "Random proxy",
            "HTTPS_PROXY": "Random https proxy",
            "NO_PROXY": "No proxy",
        }
        )
