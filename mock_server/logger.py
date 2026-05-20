"""Shared logging for mock servers — writes to both console and file."""

import sys
import os
import atexit
import datetime

_LOG_FILE = os.path.join(os.path.dirname(__file__), 'mock_server.log')
_MAX_OLD = 7  # _old_0 through _old_6

_file_handles = []


def rotate_logs():
    """Rotate current log into historical files on shutdown.

    mock_server.log → mock_server_old_0.log → mock_server_old_1.log → ...
    Keeps up to _old_6, oldest is discarded.
    """
    for f in _file_handles:
        try:
            f.close()
        except Exception:
            pass
    _file_handles.clear()

    log_dir = os.path.dirname(_LOG_FILE)

    # Remove oldest
    oldest = os.path.join(log_dir, 'mock_server_old_%d.log' % (_MAX_OLD - 1))
    if os.path.exists(oldest):
        os.remove(oldest)

    # Shift _old_5 → _old_6, ..., _old_0 → _old_1
    for i in range(_MAX_OLD - 2, -1, -1):
        src = os.path.join(log_dir, 'mock_server_old_%d.log' % i)
        dst = os.path.join(log_dir, 'mock_server_old_%d.log' % (i + 1))
        if os.path.exists(src):
            if os.path.exists(dst):
                os.remove(dst)
            os.rename(src, dst)

    # Current log → _old_0
    if os.path.exists(_LOG_FILE):
        os.rename(_LOG_FILE, os.path.join(log_dir, 'mock_server_old_0.log'))


atexit.register(rotate_logs)


def setup_logger(name):
    """Create a logger that writes to both stdout and mock_server.log."""
    log_dir = os.path.dirname(_LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir)

    f = open(_LOG_FILE, 'a', encoding='utf-8', buffering=1)
    _file_handles.append(f)

    def log(msg):
        ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = '[%s] [%s] %s' % (ts, name, msg)
        print(line)
        try:
            f.write(line + '\n')
            f.flush()
        except ValueError:
            pass  # File already closed during rotation

    log('===== %s started =====' % name)
    return log
