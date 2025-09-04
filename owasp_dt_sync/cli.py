from owasp_dt_sync.args import create_parser
from owasp_dt_sync.log import logger

def run():
    parser = create_parser()
    try:
        args = parser.parse_args()
        args.func(args)
    except (AssertionError, ValueError) as e:
        logger.error(e)
        exit(2)
    except Exception as e:
        logger.exception(e)
        exit(1)

if __name__ == "__main__":  # pragma: no cover
    run()  # pragma: no cover
