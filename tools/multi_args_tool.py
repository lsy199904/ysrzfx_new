# -*- coding: utf-8 -*-
from typing import Union, Dict, Tuple

from langchain.tools import Tool


class SupportDictArgsTool(Tool):
    def _to_args_and_kwargs(self, tool_input: Union[str, Dict]) -> Tuple[Tuple, Dict]:
        """Convert tool input to pydantic model."""
        if isinstance(tool_input, str):
            return (tool_input,), {}
        else:
            return (), tool_input
