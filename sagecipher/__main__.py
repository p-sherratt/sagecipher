import os
import sys
import stat
import click
import paramiko
import pyinotify
import threading
import time
from sagecipher import __version__
from sagecipher.cipher import Cipher, SshAgentKeyError, prompt_for_key, to_hex


@click.group()
@click.version_option(version=__version__)
def cli():
    pass


def decrypt_to_fifo(infile, outfile, mode, force, text=None):
    def write_to_fifo(notifier):
        st = os.stat(outfile)
        if not stat.S_ISFIFO(st.st_mode):
            raise click.ClickException("%s is not a FIFO!" % outfile)
        if st.st_mode & 0o777 != mode:
            raise click.ClickException("mode has changed on %s!" % outfile)

        if infile != "-":
            f_in = open(infile, "rb")
            encdata = f_in.read()
            f_in.close()

        try:
            f = open(outfile, "wb")
            data = Cipher.decrypt_bytes(encdata)
            f.write(data)
            f.close()
        except IOError:
            pass

    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm, pyinotify.ProcessEvent)
    wm.add_watch(outfile, pyinotify.IN_CLOSE_NOWRITE)
    notifier.loop(callback=write_to_fifo)


def _checkoutfile_file(outfile, force):
    if os.path.isfile(outfile):
        if force:
            os.unlink(outfile)
        else:
            raise click.ClickException(
                "Output file %s exists and --force is not specified!" % outfile
            )


def decrypt_to_file(infile, outfile, mode, force):
    if infile == "-":
        encdata = sys.stdin.buffer.read()
    else:
        with open(infile, "rb") as f:
            encdata = f.read()

    data = Cipher.decrypt_bytes(encdata)

    if outfile == "-":
        sys.stdout.buffer.write(data)
    else:
        with open(outfile, "w") as f:
            f.write(data)


@cli.command()
def list_keys():
    """List keys from SSH agent"""
    agent = paramiko.Agent()
    keys = agent.get_keys()
    for key in agent.get_keys():
        # paramiko doesn't expose key comments (yet?)
        keystr = "[{}] {}".format(key.get_name(), to_hex(key.get_fingerprint()))
        click.echo(keystr)
    agent.close()

@cli.command()
@click.argument("infile", default="-")
@click.argument("outfile", default="-")
@click.option("--mode", default="600", help="Octal mode of output file (default: 600)")
@click.option(
    "--fifo/--file", default=True, is_flag=True, help="Type of output (default: --fifo)"
)
@click.option(
    "--force", is_flag=True, help="Overwrite output file/fifo if it already exists"
)
@click.option(
    "--tether/--no-tether",
    default=True,
    is_flag=True,
    help="Tether to parent process, and forcefully die when the parent dies (default: --tether)",
)
def decrypt(infile, outfile, mode, fifo, force, tether):
    """Decrypt contents of INPUT file to OUTPUT file/fifo.
    
    If --type is 'fifo', the process will loop forever, attempting to open the fifo for
    writing, and when opened will write the decrypted contents out.  It is recommended
    to run this in the background of a shell session.

    To read from STDIN or write to STDOUT, specify '-' as the INPUT or OUTPUT
    file respectively.
    """

    if outfile == "-":
        fifo = False

    mode = int(mode, 8)
    umask = int("777", 8) - mode
    os.umask(umask)

    args = [infile, outfile, mode, force]

    if fifo:
        if infile == "-":
            args.append(sys.stdin.read())

        try:
            st = os.stat(outfile)
            if st and not stat.S_ISFIFO(st.st_mode):
                raise click.ClickException(
                    "Output file %s exists and is not a FIFO!" % outfile
                )
            elif st:
                os.unlink(outfile)
        except (IOError, OSError):
            pass

        os.mkfifo(outfile)
        os.chmod(outfile, mode)

        if tether:
            # run until parent pid changes (i.e. due to termination of shell)
            ppid = os.getppid()

            def ppid_watchdog():
                while True:
                    if ppid != os.getppid():
                        os._exit(0)
                    time.sleep(1)

            t = threading.Thread(target=ppid_watchdog)
            t.daemon = True
            t.start()

        decrypt_to_fifo(*args)
    else:
        _checkoutfile_file(outfile, force)
        decrypt_to_file(*args)


@cli.command()
@click.argument("infile", default="-")
@click.argument("outfile", default="-")
@click.option("--mode", default="600", help="Octal mode of output file (default: 600)")
@click.option(
    "--force", is_flag=True, help="Overwrite output file if it already exists"
)
@click.option(
    "--key",
    help="SSH public key (HEX) fingerprint to use. If not specified, "
    + "sagecipher will list all available keys from ssh-agent "
    + "and prompt for selection.",
)
def encrypt(infile, outfile, mode, force, key):
    """Encrypt contents of INPUT file to OUTPUT file.

    To read from STDIN or write to STDOUT, specify '-' as the INPUT or OUTPUT
    file respectively.
    """

    if key is not None:
        key = key.replace(":", "").lower()
        if len(key) != 32:
            raise click.ClickException("Invalid key specified")

    try:
        if key is None:
            key = prompt_for_key()

        if infile == "-":
            click.echo("Reading from STDIN...\n")
            data = sys.stdin.read().encode("utf8")
        else:
            with open(infile, "r") as f:
                data = f.read()

        encdata = Cipher.encrypt_bytes(data, key)

        if outfile == "-":
            sys.stdout.buffer.write(encdata)
        else:
            _checkoutfile_file(outfile, force)
            with open(outfile, "wb") as f:
                f.write(encdata)

    except SshAgentKeyError as e:
        raise click.ClickException(str(e))


if __name__ == "__main__":
    cli()
