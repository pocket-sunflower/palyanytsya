import logging

import coloredlogs

logging.basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
                    datefmt="%H:%M:%S")
logger = logging.getLogger("PALYANYTSYA")
coloredlogs.install(
    logger=logger,
    level=logging.INFO,
    fmt="{asctime} {name} {process} [{levelname}] {message}",
    style="{",
    datefmt="%H:%M:%S"
)
logger.setLevel("INFO")
