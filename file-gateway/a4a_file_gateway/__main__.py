"""Run the file gateway. Configuration is read from the environment, never from a file."""
from __future__ import annotations

import logging
import os
import sys

from .config import ConfigError
from .service import build_gateway, serve

log = logging.getLogger("a4a.file_gateway")


def main(argv: list[str] | None = None) -> int:
    del argv
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        gateway = build_gateway(os.environ)
    except ConfigError as exc:
        log.error("%s", exc)
        return 2
    return serve(gateway)


if __name__ == "__main__":
    sys.exit(main())
