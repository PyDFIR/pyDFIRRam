import os
import sys
from .LoggerUtil import set_up_logging

project_name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
if not set_up_logging(
    console_log_output="stdout",
    console_log_level="warning",
    console_log_color=True,
    logfile_file=project_name + ".log",
    logfile_log_level="debug",
    logfile_log_color=False,
    log_line_template="%(color_on)s[%(created)d] [%(threadName)s] [%(asctime)s] [%(levelname)s] %(message)s%(color_off)s",
):
    raise "Failed to set up logging, aborting."
