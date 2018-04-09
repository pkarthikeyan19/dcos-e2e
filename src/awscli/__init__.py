import io
import json
import logging
import subprocess
import sys
import tarfile
import uuid
from ipaddress import IPv4Address
from pathlib import Path
from shutil import rmtree
from subprocess import CalledProcessError
from tempfile import gettempdir
from typing import (  # noqa: F401
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

import click
import click_spinner
import docker
import urllib3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from docker.models.containers import Container
from passlib.hash import sha512_crypt

from dcos_e2e.backends import Docker
from dcos_e2e.cluster import Cluster
from dcos_e2e.node import Node
def _set_logging(
    ctx: click.core.Context,
    param: Union[click.core.Option, click.core.Parameter],
    value: Optional[Union[int, bool, str]],
) -> None:
    """
    Set logging level depending on the chosen verbosity.
    """
    # We "use" variables to satisfy linting tools.
    for _ in (ctx, param):
        pass

    value = min(value, 2)
    value = max(value, 0)
    verbosity_map = {
        0: logging.WARNING,
        1: logging.DEBUG,
        2: logging.INFO,
    }
    logging.disable(verbosity_map[int(value or 0)])


@click.option(
    '-v',
    '--verbose',
    count=True,
    callback=_set_logging,
)
@click.group(name='dcos-aws')
@click.version_option()
def dcos_aws(verbose: None) -> None:
    """
    Manage DC/OS clusters on Docker.
    """
    # We "use" variables to satisfy linting tools.
    for _ in (verbose, ):
        pass

@dcos_aws.command('create')
def create(
    agents: int,
    artifact: str,
    cluster_id: str,
    extra_config: Dict[str, Any],
    linux_distribution: str,
    masters: int,
    public_agents: int,
    license_key: Optional[str],
    security_mode: Optional[str],
    copy_to_master: List[Tuple[Path, Path]],
    workspace_dir: Optional[Path],
) -> None:
    """
    XXX
    """
    base_workspace_dir = workspace_dir or Path(gettempdir())
    workspace_dir = base_workspace_dir / uuid.uuid4().hex

    doctor_message = 'Try `dcos-aws doctor` for troubleshooting help.'
    ssh_keypair_dir = workspace_dir / 'ssh'
    ssh_keypair_dir.mkdir(parents=True)
    public_key_path = ssh_keypair_dir / 'id_rsa.pub'
    private_key_path = ssh_keypair_dir / 'id_rsa'
    _write_key_pair(
        public_key_path=public_key_path,
        private_key_path=private_key_path,
    )

    # TODO: How to find if artifact is enterprise?
    # Download?

    if enterprise:
        superuser_username = 'admin'
        superuser_password = 'admin'

        enterprise_extra_config = {
            'superuser_username': superuser_username,
            'superuser_password_hash': sha512_crypt.hash(superuser_password),
            'fault_domain_enabled': False,
        }
        if license_key is not None:
            key_contents = Path(license_key).read_text()
            enterprise_extra_config['license_key_contents'] = key_contents

        extra_config = {**enterprise_extra_config, **extra_config}
        if security_mode is not None:
            extra_config['security'] = security_mode

    # TODO Add label option to AWS backend
    cluster_backend = AWS(
        linux_distribution=LINUX_DISTRIBUTIONS[linux_distribution],
        docker_container_labels={
            CLUSTER_ID_LABEL_KEY: cluster_id,
            WORKSPACE_DIR_LABEL_KEY: str(workspace_dir),
            VARIANT_LABEL_KEY: 'ee' if enterprise else '',
        },
        docker_master_labels={'node_type': 'master'},
        docker_agent_labels={'node_type': 'agent'},
        docker_public_agent_labels={'node_type': 'public_agent'},
        workspace_dir=workspace_dir,
    )

    try:
        cluster = Cluster(
            cluster_backend=cluster_backend,
            masters=masters,
            agents=agents,
            public_agents=public_agents,
            files_to_copy_to_installer=files_to_copy_to_installer,
        )
    except CalledProcessError as exc:
        click.echo('Error creating cluster.', err=True)
        click.echo(doctor_message)
        sys.exit(exc.returncode)

    nodes = {
        *cluster.masters,
        *cluster.agents,
        *cluster.public_agents,
    }

    for node in nodes:
        node.run(
            args=['echo', '', '>>', '/root/.ssh/authorized_keys'],
            shell=True,
        )
        node.run(
            args=[
                'echo',
                public_key_path.read_text(),
                '>>',
                '/root/.ssh/authorized_keys',
            ],
            shell=True,
        )

    for node in cluster.masters:
        for path_pair in copy_to_master:
            local_path, remote_path = path_pair
            node.send_file(
                local_path=local_path,
                remote_path=remote_path,
            )

    try:
        with click_spinner.spinner():
            cluster.install_dcos_from_path(
                build_artifact=artifact_path,
                extra_config=extra_config,
            )
    except CalledProcessError as exc:
        click.echo('Error installing DC/OS.', err=True)
        click.echo(doctor_message)
        cluster.destroy()
        sys.exit(exc.returncode)

    click.echo(cluster_id)
