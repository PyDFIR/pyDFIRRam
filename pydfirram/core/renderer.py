"""todo"""

import abc
import json

from typing import Any

import pandas as pd
from loguru import logger


class Renderer(metaclass=abc.ABCMeta):
    """Abstract class for rendering data in different formats.

    Attributes:
        output_format: The output format to render the data in.
        data: The data to render.
    """

    @abc.abstractmethod
    @staticmethod
    def render(data: Any):
        """Render the data in the specified format."""


class DataframeRenderer(Renderer):
    """Class for rendering data in a tabular format.

    It is useful for displaying data in a human-readable format.
    This can be multiple types of data, such as a pandas DataFrame, python dict, ...
    """

    @staticmethod
    def render(data: Any):
        """Render the data in a tabular format."""
        try:
            formatted = pd.DataFrame(data)
        except Exception as e:
            logger.error("Data cannot be rendered as a DataFrame.")
            raise e

        return formatted


class JsonRenderer(Renderer):
    """Class for rendering data in JSON format.

    It is useful for displaying data in a machine-readable format.
    This can be multiple types of data, such as a pandas DataFrame, python dict, ...
    """

    @staticmethod
    def render(data: Any):
        """Render the data in JSON format."""
        try:
            formatted = json.dumps(data)
        except Exception as e:
            logger.error("Data cannot be rendered as JSON.")
            raise e

        return formatted
