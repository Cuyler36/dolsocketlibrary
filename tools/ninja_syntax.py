"""Minimal Python module for generating .ninja files.

Trimmed-down version of ninja's misc/ninja_syntax.py (Apache 2.0).
"""

import re
import textwrap
from io import StringIO
from pathlib import Path
from typing import Dict, List, Optional, Union

NinjaPath = Union[str, Path]
NinjaPaths = Union[List[str], List[Path], List[NinjaPath], List[Optional[str]]]
NinjaPathOrPaths = Union[NinjaPath, NinjaPaths]


def escape_path(word: str) -> str:
    return word.replace("$ ", "$$ ").replace(" ", "$ ").replace(":", "$:")


def serialize_path(input: Optional[NinjaPath]) -> str:
    if not input:
        return ""
    if isinstance(input, Path):
        return str(input).replace("\\", "/")
    return str(input)


def serialize_paths(input: Optional[NinjaPathOrPaths]) -> List[str]:
    if isinstance(input, list):
        return [serialize_path(path) for path in input if path]
    return [serialize_path(input)] if input else []


class Writer:
    def __init__(self, output: StringIO, width: int = 78) -> None:
        self.output = output
        self.width = width

    def newline(self) -> None:
        self.output.write("\n")

    def comment(self, text: str) -> None:
        for line in textwrap.wrap(text, self.width - 2, break_long_words=False, break_on_hyphens=False):
            self.output.write("# " + line + "\n")

    def variable(self, key: str, value: Optional[Union[str, List[str]]], indent: int = 0) -> None:
        if value is None:
            return
        if isinstance(value, list):
            value = " ".join(filter(None, value))
        self._line(f"{key} = {value}", indent)

    def pool(self, name: str, depth: int) -> None:
        self._line(f"pool {name}")
        self.variable("depth", str(depth), indent=1)

    def rule(
        self,
        name: str,
        command: str,
        description: Optional[str] = None,
        depfile: Optional[NinjaPath] = None,
        generator: bool = False,
        pool: Optional[str] = None,
        restat: bool = False,
        deps: Optional[str] = None,
    ) -> None:
        self._line(f"rule {name}")
        self.variable("command", command, indent=1)
        if description:
            self.variable("description", description, indent=1)
        if depfile:
            self.variable("depfile", serialize_path(depfile), indent=1)
        if generator:
            self.variable("generator", "1", indent=1)
        if pool:
            self.variable("pool", pool, indent=1)
        if restat:
            self.variable("restat", "1", indent=1)
        if deps:
            self.variable("deps", deps, indent=1)

    def build(
        self,
        outputs: NinjaPathOrPaths,
        rule: str,
        inputs: Optional[NinjaPathOrPaths] = None,
        implicit: Optional[NinjaPathOrPaths] = None,
        order_only: Optional[NinjaPathOrPaths] = None,
        variables: Optional[Dict[str, Optional[Union[str, List[str]]]]] = None,
        implicit_outputs: Optional[NinjaPathOrPaths] = None,
    ) -> List[str]:
        outputs = serialize_paths(outputs)
        out_outputs = [escape_path(x) for x in outputs]
        all_inputs = [escape_path(x) for x in serialize_paths(inputs)]

        if implicit:
            all_inputs.append("|")
            all_inputs.extend(escape_path(x) for x in serialize_paths(implicit))
        if order_only:
            all_inputs.append("||")
            all_inputs.extend(escape_path(x) for x in serialize_paths(order_only))
        if implicit_outputs:
            out_outputs.append("|")
            out_outputs.extend(escape_path(x) for x in serialize_paths(implicit_outputs))

        self._line("build %s: %s" % (" ".join(out_outputs), " ".join([rule] + all_inputs)))

        if variables:
            for key, val in variables.items():
                self.variable(key, val, indent=1)

        return outputs

    def default(self, paths: NinjaPathOrPaths) -> None:
        self._line("default %s" % " ".join(serialize_paths(paths)))

    def _count_dollars_before_index(self, s: str, i: int) -> int:
        dollar_count = 0
        dollar_index = i - 1
        while dollar_index > 0 and s[dollar_index] == "$":
            dollar_count += 1
            dollar_index -= 1
        return dollar_count

    def _line(self, text: str, indent: int = 0) -> None:
        leading_space = "  " * indent
        while len(leading_space) + len(text) > self.width:
            available_space = self.width - len(leading_space) - len(" $")
            space = available_space
            while True:
                space = text.rfind(" ", 0, space)
                if space < 0 or self._count_dollars_before_index(text, space) % 2 == 0:
                    break
            if space < 0:
                space = available_space - 1
                while True:
                    space = text.find(" ", space + 1)
                    if space < 0 or self._count_dollars_before_index(text, space) % 2 == 0:
                        break
            if space < 0:
                break
            self.output.write(leading_space + text[0:space] + " $\n")
            text = text[space + 1 :]
            leading_space = "  " * (indent + 2)
        self.output.write(leading_space + text + "\n")

    def close(self) -> None:
        self.output.close()


def escape(string: str) -> str:
    assert "\n" not in string, "Ninja syntax does not allow newlines"
    return string.replace("$", "$$")
