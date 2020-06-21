import pytest
import re
import sys
import os
import subprocess


@pytest.fixture(scope="session", autouse=True)
def setup_ssh_agent():
    if sys.platform in ("linux", "darwin"):
        ssh_key_path = "/tmp/ssh-testkey.{}".format(os.getpid())
        subprocess.run(
            [
                "ssh-keygen",
                "-b",
                "2048",
                "-t",
                "rsa",
                "-f",
                ssh_key_path,
                "-q",
                "-N",
                "",
            ]
        )

        env_sh = subprocess.check_output("ssh-agent")
        for cmd in env_sh.decode().splitlines():
            env_cmd = re.search(r"(\S+)=(\S+);", cmd)
            if env_cmd:
                os.environ[env_cmd.group(1)] = env_cmd.group(2)

        subprocess.check_output(["ssh-add", ssh_key_path], stderr=subprocess.STDOUT)

        os.unlink(ssh_key_path)

    else:
        raise NotImplementedError(
            "Tests not implemented for platform '{}'".format(sys.platform)
        )
