import contextlib
import json
import os
import tempfile
import time
import unittest

import httpx
from testcontainers.core.container import DockerContainer

from lsst.daf.butler.remote_butler._factory import RemoteButlerFactory
from lsst.daf.butler.tests.utils import MetricTestRepo

TESTDIR = os.path.abspath(os.path.dirname(__file__))


@contextlib.contextmanager
def _run_server_docker():
    with tempfile.TemporaryDirectory() as temp_dir:
        # Ensure the repository directory will be readable inside the container
        os.chmod(temp_dir, 0o755)

        MetricTestRepo(
            root=temp_dir, configFile=os.path.join(TESTDIR, "../tests", "config/basic/butler.yaml")
        )

        port = 8080
        butler_root = "/butler_root"
        repo_name = "testserver"
        repository_config = {repo_name: {"config_uri": butler_root, "authorized_groups": ["*"]}}

        docker_image = os.getenv("BUTLER_SERVER_DOCKER_IMAGE")
        if not docker_image:
            raise Exception("BUTLER_SERVER_DOCKER_IMAGE must be set")
        container = (
            DockerContainer(docker_image)
            .with_exposed_ports(port)
            .with_env("DAF_BUTLER_SERVER_REPOSITORIES", json.dumps(repository_config))
            .with_env("DAF_BUTLER_SERVER_GAFAELFAWR_URL", "http://gafaelfawr.example")
            .with_env("DAF_BUTLER_SERVER_AUTHENTICATION", "rubin_science_platform")
            .with_volume_mapping(temp_dir, butler_root, "rw")
        )

        with container:
            server_host = container.get_container_host_ip()
            server_port = container.get_exposed_port(port)
            server_url = f"http://{server_host}:{server_port}"
            full_server_url = f"{server_url}/api/butler/repo/{repo_name}"
            try:
                _wait_for_startup(server_url)
                yield full_server_url
            finally:
                (stdout, stderr) = container.get_logs()
                if stdout:
                    print("STDOUT:")
                    print(stdout.decode())
                if stderr:
                    print("STDERR:")
                    print(stderr.decode())


def _wait_for_startup(server_url):
    max_retries = 30
    attempt = 0
    exception = None
    while attempt < max_retries:
        attempt += 1
        try:
            httpx.get(server_url)
            return
        except Exception as e:
            exception = e
            time.sleep(1)

    raise RuntimeError("Timed out waiting for server port to open on container.") from exception


class ButlerDockerTestCase(unittest.TestCase):
    """Simple smoke test to ensure the server can start up and respond to
    requests
    """

    @classmethod
    def setUpClass(cls):
        cls.server_uri = cls.enterClassContext(_run_server_docker())

    def test_get_dataset_type(self):
        client = httpx.Client(
            headers={
                # Mock Gafaelfawr authentication headers
                "X-Auth-Request-User": "fake-username",
                "X-Auth-Request-Token": "fake-delegated-token",
            }
        )
        butler = RemoteButlerFactory.create_factory_for_url(
            self.server_uri, client
        ).create_butler_for_access_token("fake-access-token")
        dataset_type = butler.get_dataset_type("test_metric_comp")
        self.assertEqual(dataset_type.name, "test_metric_comp")


if __name__ == "__main__":
    unittest.main()
