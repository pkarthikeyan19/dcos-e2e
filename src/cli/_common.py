"""
Common code for CLI modules.
"""

from typing import Set

import docker

from dcos_e2e.distributions import Distribution
from dcos_e2e.docker_storage_drivers import DockerStorageDriver
from dcos_e2e.docker_versions import DockerVersion

LINUX_DISTRIBUTIONS = {
    'centos-7': Distribution.CENTOS_7,
    'ubuntu-16.04': Distribution.UBUNTU_16_04,
    'coreos': Distribution.COREOS,
    'fedora-23': Distribution.FEDORA_23,
    'debian-8': Distribution.DEBIAN_8,
}

DOCKER_VERSIONS = {
    '1.13.1': DockerVersion.v1_13_1,
    '1.11.2': DockerVersion.v1_11_2,
}

DOCKER_STORAGE_DRIVERS = {
    'aufs': DockerStorageDriver.AUFS,
    'overlay': DockerStorageDriver.OVERLAY,
    'overlay2': DockerStorageDriver.OVERLAY_2,
}

CLUSTER_ID_LABEL_KEY = 'dcos_e2e.cluster_id'
WORKSPACE_DIR_LABEL_KEY = 'dcos_e2e.workspace_dir'
VARIANT_LABEL_KEY = 'dcos_e2e.variant'


def existing_cluster_ids() -> Set[str]:
    """
    Return the IDs of existing clusters.
    """
    client = docker.from_env(version='auto')
    filters = {'label': CLUSTER_ID_LABEL_KEY}
    containers = client.containers.list(filters=filters)
    return set(
        [container.labels[CLUSTER_ID_LABEL_KEY] for container in containers]
    )