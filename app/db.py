"""Shared connection pools, one per database URL.

Opening a connection per call costs a TCP and auth handshake each time, and under load it
exhausts local ports (closed sockets sit in TIME_WAIT). A small pool reuses connections.
"""

import atexit
from functools import lru_cache

from psycopg_pool import ConnectionPool


@lru_cache
def get_pool(dsn: str) -> ConnectionPool:
    pool = ConnectionPool(dsn, min_size=1, max_size=8, open=False, kwargs={"connect_timeout": 5})
    pool.open()
    atexit.register(pool.close)
    return pool
