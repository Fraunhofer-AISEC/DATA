from pylatex import Package
from pylatex.base_classes import ContainerCommand, Environment


class TextColorExt(ContainerCommand):
    """An environment which changes the text color of the data."""

    _latex_name = "textcolor"
    _repr_attributes_mapping = {"color": "arguments"}

    packages = [Package("xcolor")]

    def __init__(self, color, data, **kwargs):
        """
        Args
        ----
        color: str
            The color to set for the data inside of the environment.
        data: str or `~.LatexObject`
            The string or LatexObject to be formatted.
        """

        super().__init__(arguments=color, data=data, **kwargs)


class LstListing(Environment):
    packages = [Package("listings"), Package("xcolor")]
    escape = False
    content_separator = "\n"
