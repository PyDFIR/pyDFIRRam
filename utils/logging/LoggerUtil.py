import logging
import sys

"""
Tu use the logging utils configuration juste import utils in main file
nice Franglish u know ;)
"""


class LogFormatter(logging.Formatter):
    COLOR_CODES = {
        logging.CRITICAL: "\033[1;35m",  # bright/bold magenta
        logging.ERROR: "\033[1;31m",  # bright/bold red
        logging.WARNING: "\033[1;33m",  # bright/bold yellow
        logging.INFO: "\033[0;37m",  # white / light gray
        logging.DEBUG: "\033[1;30m",  # bright/bold black / dark gray
    }

    RESET_CODE = "\033[0m"

    def __init__(self, color, *args, **kwargs):
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.color = color

    def format(self, record, *args, **kwargs):
        if self.color is True and record.levelno in self.COLOR_CODES:
            record.color_on = self.COLOR_CODES[record.levelno]
            record.color_off = self.RESET_CODE
        else:
            record.color_on = ""
            record.color_off = ""
        return super(LogFormatter, self).format(record, *args, **kwargs)


# Set up logging
def set_up_logging(
    console_log_output,
    console_log_level,
    console_log_color,
    logfile_file,
    logfile_log_level,
    logfile_log_color,
    log_line_template,
):
    # Create logger
    # For simplicity, we use the root logger, i.e. call 'logging.getLogger()'
    # without name argument. This way we can simply use module methods for
    # for logging throughout the script. An alternative would be exporting
    # the logger, i.e. 'global logger; logger = logging.getLogger("<name>")'
    logger = logging.getLogger()

    # Set global log level to 'debug' (required for handler levels to work)
    logger.setLevel(logging.DEBUG)

    # create console handler
    console_log_output = console_log_output.lower()
    if console_log_output == "stdout":
        console_log_output = sys.stdout
    elif console_log_output == "stderr":
        console_log_output = sys.stderr
    else:
        print(
            "LOGGER ERROR: Failed to set console output: invalid output: '%s'"
            % console_log_output
        )
        return False
    console_handler = logging.StreamHandler(console_log_output)

    # Set console log level
    try:
        # only accepts uppercase level names
        console_handler.setLevel(console_log_level.upper())
    except NameError:
        print(
            "LOGGER ERROR: Failed to set console log level: invalid level: '%s'"
            % console_log_level
        )
        return False

    # Create and set formatter, add console handler to logger
    console_formatter = LogFormatter(fmt=log_line_template, color=console_log_color)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Create log file handler
    try:
        logFile_handler = logging.FileHandler(logfile_file)
    except Exception as exception:
        print("LOGGER ERROR: Failed to set up file: %s" % str(exception))
        return False

    # Set log file log level
    try:
        # only accept uppercase level names
        logFile_handler.setLevel(logfile_log_level.upper())
    except Exception:
        print(
            "LOGGER ERROR: Failed to set up log file log level: invalid level: '%s'"
            % logfile_log_level
        )
        return False

    # Create and set formatter, and log file handler to logger
    logfile_formatter = LogFormatter(fmt=log_line_template, color=logfile_log_color)
    logFile_handler.setFormatter(logfile_formatter)
    logger.addHandler(logFile_handler)

    # success
    print("Logger successfully setup")
    return True
