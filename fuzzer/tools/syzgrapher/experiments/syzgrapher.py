
# Utility wrapper around some command line tools

import os
import pathlib
import subprocess

import graphviz

MUTATE_BIN = pathlib.Path(__file__).parent.parent / "mutation-tests" / "main"
TO_GRAPHVIZ_BIN = pathlib.Path(__file__).parent.parent / "to-graphviz" / "main"


def mutate(os: str, arch: str, program: str, seed: int, schema: str = "", verbose: bool = False) -> str:
    args = [
        str(MUTATE_BIN),
        '-os', os,
        '-arch', arch,
        '-seed', str(seed),
    ]
    if verbose:
        args.append('-verbose')
    if schema:
        args.extend(['-schema', schema])
    
    return subprocess.check_output(
        args,
        input=program.encode("latin-1"),
        stderr=subprocess.PIPE
    ).decode("latin-1")


def to_graphviz(os: str, arch: str, program: str) -> graphviz.Digraph:
    return graphviz.Source(
        subprocess.check_output(
            [
                str(TO_GRAPHVIZ_BIN),
                '-os', os,
                '-arch', arch,
            ],
            input=program.encode("latin-1"),
        ).decode("latin-1"),
        format="svg",
    )
