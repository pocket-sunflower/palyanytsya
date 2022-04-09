import logging

logging.basicConfig(format='[%(asctime)s - %(levelname)s] %(message)s',
                    datefmt="%H:%M:%S")
logger = logging.getLogger("PALYANYTSYA")
logger.setLevel("INFO")
