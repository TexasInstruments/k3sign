"""Helper Functions"""
from shutil import copyfileobj
import logging


def concat_file(output_file_name, input_file_list):
    """Concatenate the input file list into the output file name"""

    with open(output_file_name, 'wb') as out_fh:
        logging.debug("Opened output file %s", output_file_name)
        for inp_file_name in input_file_list:
            with open(inp_file_name, 'rb') as inp_fh:
                logging.debug("Opened input file %s", inp_file_name)
                copyfileobj(inp_fh, out_fh)
