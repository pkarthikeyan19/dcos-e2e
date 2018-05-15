"""
Common utilities for end to end tests.
"""

import logging
from pprint import pformat
import subprocess
from subprocess import PIPE, STDOUT, CompletedProcess, Popen
from typing import Dict, List, Optional, Union

logging.basicConfig(level=logging.DEBUG)
CMD = logging.getLogger('dcos_e2e.cmd')
OUT = logging.getLogger('dcos_e2e.out')


def safe_decode(b):
    """
    Decode a bytestring to Unicode with a safe fallback
    """
    try:
        # Try UTF-8 first
        return b.decode('utf8')
    except UnicodeDecodeError:
        # Fallback to a decoding which should always work. For the many
        # encodings that are a superset of ASCII, it may even be legible.
        return b.decode('ascii', 'backslashreplace')


def run_subprocess(
    args: List[str],
    log_output_live: bool,
    cwd: Optional[Union[bytes, str]] = None,
    env: Optional[Dict[str, str]] = None,
    pipe_output: bool = True,
) -> CompletedProcess:
    """
    Run a command in a subprocess.

    Args:
        args: See :py:func:`subprocess.run`.
        log_output_live: If `True`, log output live. If `True`, stderr is
            merged into stdout in the return value.
        cwd: See :py:func:`subprocess.run`.
        env: See :py:func:`subprocess.run`.
        pipe_output: If ``True``, pipes are opened to stdout and stderr.
            This means that the values of stdout and stderr will be in
            the returned ``subprocess.CompletedProcess`` and optionally
            sent to a logger, given ``log_output_live``.
            If ``False``, no output is sent to a logger and the values are
            not returned.

    Returns:
        See :py:func:`subprocess.run`.

    Raises:
        subprocess.CalledProcessError: See :py:func:`subprocess.run`.
        Exception: An exception was raised in getting the output from the call.
        ValueError: ``log_output_live`` is ``True`` and ``pipe_output`` is
            ``False``.
    """
    if log_output_live and not pipe_output:
        raise ValueError(
            '`log_output_live` cannot be `True` if `pipe_output` is `False`.'
        )

    process_stdout = PIPE if pipe_output else None
    # It is hard to log output of both stdout and stderr live unless we
    # combine them.
    # See http://stackoverflow.com/a/18423003.
    if log_output_live:
        process_stderr = STDOUT
    else:
        process_stderr = PIPE

    for line in pformat(args, width=160, compact=True).split('\n'):
        CMD.info(line)

    with Popen(
        args=args,
        cwd=cwd,
        stdout=process_stdout,
        stderr=process_stderr,
        env=env,
    ) as process:
        try:
            if log_output_live:
                stdout = b''
                stderr = b''
                for line in process.stdout:
                    OUT.debug(safe_decode(line.rstrip()))
                    stdout += line
                # stderr/stdout are not readable anymore which usually means
                # that the child process has exited.
            else:
                stdout, stderr = process.communicate()
        except Exception:  # pragma: no cover
            # Ensure the subprocess(es) are terminated.
            # This may not happen while running tests so we ignore coverage.
            process.terminate()
            try:
                process.wait(1)
            except subprocess.TimeoutExpired:
                process.kill()
            raise
    # Exiting context manager wait()s for the process and sets the return code.
    if stderr:
        if process.returncode == 0:
            level = logging.WARNING
        else:
            level = logging.ERROR
        for line in stderr.rstrip().split(b'\n'):
            OUT.log(level, safe_decode(line))
    if process.returncode != 0:
        CMD.error('Exit status: %s', process.returncode)
        raise subprocess.CalledProcessError(
            process.returncode,
            args,
            output=stdout,
            stderr=stderr,
        )
    return CompletedProcess(args, process.returncode, stdout, stderr)
