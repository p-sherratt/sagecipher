
import os
import sys
import stat
import click
import pyinotify
import threading
import time
from . import __version__, encrypt_string, decrypt_string


@click.group()
@click.version_option(version=__version__)
def cli():
    pass

def decrypt_to_fifo(_input, _output, _mode, _force, text=None):
    def write_to_fifo(notifier):
        st = os.stat(_output)
        if not stat.S_ISFIFO(st.st_mode):
            raise click.ClickException('%s is not a FIFO!' % _output)
        if (st.st_mode & 0o777 != _mode):
            raise click.ClickException('mode has changed on %s!' % _output)

        if _input != '-':
            f_in = open(_input, 'rb')
            text = f_in.read()
            f_in.close()

        try:
            f = open(_output, 'w')
            text = decrypt_string(text)
            f.write(text)
            f.close()
        except IOError:
            pass
        finally:
            text = str(0x00) * len(text)

    wm = pyinotify.WatchManager()
    notifier = pyinotify.Notifier(wm, pyinotify.ProcessEvent)
    wm.add_watch(_output, pyinotify.IN_CLOSE_NOWRITE)
    notifier.loop(callback=write_to_fifo)


def _check_output_file(a):
    if os.path.isfile(a['output']):
        if a['force']:
            os.unlink(a['output'])
        else:
            raise click.ClickException('Output file %s exists and --force is not specified!' % a['output'])

def decrypt_to_file(_input, _output, _mode, _force):
    if _input == '-':
        text = sys.stdin.read()
    else:
        with open(_input) as f:
            text = f.read()

    text = decrypt_string(text)

    if _output == '-':
        sys.stdout.write(text)
    else:
        with open(_output, 'w') as f:
            f.write(text)


@cli.command()
@click.argument('input')
@click.argument('output')
@click.option('--mode', default='600', help="Octal mode of output file (default: 600)")
@click.option('--type', default='fifo', type=click.Choice(['fifo', 'file']), help="Type of output (default: fifo)")
@click.option('--force', is_flag=True, help="Overwrite output file/fifo if it already exists")
def decrypt(**a):
    """Decrypt contents of INPUT file to OUTPUT file/fifo.
    
    If --type is 'fifo', the process will loop forever, attempting to open the fifo for
    writing, and when opened will write the decrypted contents out.  It is recommended
    to run this in the background of a shell session.

    To read from STDIN or write to STDOUT, specify '-' as the INPUT or OUTPUT
    file respectively.
    """

    if a['output'] == '-':
        a['type'] = 'file'

    a['mode'] = int(a['mode'], 8)
    umask = int('777',8)-a['mode']
    os.umask(umask)

    args = [a[k] for k in ('input', 'output', 'mode', 'force')]

    if a['type'] == 'fifo':
        if a['input'] == '-':
            args.append(sys.stdin.read())

        try:
            st = os.stat(a['output'])
            if st and not stat.S_ISFIFO(st.st_mode):
                raise click.ClickException('Output file %s exists and is not a FIFO!' % a['output'])
            elif st:
                os.unlink(a['output'])
        except (IOError, OSError):
            pass

        os.mkfifo(a['output'])
        os.chmod(a['output'], a['mode'])

        # if parent changes (ie shell session terminated), lets do a suicide dance.
        ppid = os.getppid()
        def ppid_watchdog():
            while True:
                with open('/tmp/moo', 'a') as f:
                    f.write(str(os.getppid()) + "\n")

                if ppid != os.getppid():
                    os._exit(0)
                time.sleep(1)

        t = threading.Thread(target=ppid_watchdog)
        t.daemon = True
        t.start()
        
        decrypt_to_fifo(*args)
    else:
        _check_output_file(a)
        decrypt_to_file(*args)

@cli.command()
@click.argument('input')
@click.argument('output')
@click.option('--mode', default='600', help="Octal mode of output file (default: 600)")
@click.option('--force', is_flag=True, help="Overwrite output file/fifo if it already exists")
def encrypt(**a):
    """Encrypt contents of INPUT file to OUTPUT file.

    To read from STDIN or write to STDOUT, specify '-' as the INPUT or OUTPUT
    file respectively.
    """

    if a['input'] == '-':
        text = sys.stdin.read()
    else:
        with open(a['input'], 'r') as f:
            text = f.read()

    text = encrypt_string(text)

    if a['output'] == '-':
        sys.stdout.write(text)
    else:
        _check_output_file(a)
        with open(a['output'], 'wb') as f:
            f.write(text)


if __name__ == "__main__":
    cli()
