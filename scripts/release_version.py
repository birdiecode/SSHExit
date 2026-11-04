#!/usr/bin/env python3
"""Calculate and optionally apply an Android semantic-version bump."""
import argparse
from dataclasses import dataclass
from pathlib import Path
import re

KINDS = {
    "Patch - bug fixes": "patch",
    "Minor - new features": "minor",
    "Major - breaking changes": "major",
}
CODE = re.compile(r"(?m)^([ \t]*versionCode[ \t]+)([0-9]+)([ \t]*)$")
NAME = re.compile(r"""(?m)^([ \t]*versionName[ \t]+)(['"])([^'"]*)\2([ \t]*)$""")
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
MAX_CODE = 2100000000

@dataclass(frozen=True)
class VersionPlan:
    version: str
    code: int
    source: str

def plan(source, kind, expected=None):
    if kind not in KINDS:
        raise ValueError("Unknown release type")
    codes, names = list(CODE.finditer(source)), list(NAME.finditer(source))
    if len(codes) != 1 or len(names) != 1:
        raise ValueError("Expected exactly one versionCode and versionName")
    current = SEMVER.fullmatch(names[0].group(3))
    if current is None:
        raise ValueError("Current versionName must use X.Y.Z")
    major, minor, patch = map(int, current.groups())
    bump = KINDS[kind]
    if bump == "major":
        major, minor, patch = major + 1, 0, 0
    elif bump == "minor":
        minor, patch = minor + 1, 0
    else:
        patch += 1
    version = f"{major}.{minor}.{patch}"
    code = int(codes[0].group(2)) + 1
    if not 1 <= code <= MAX_CODE:
        raise ValueError("Next versionCode exceeds the Android limit")
    if expected is not None and version != expected:
        raise ValueError("Calculated version differs from the requested build; run Android Release again")
    updated = CODE.sub(lambda m: f"{m.group(1)}{code}{m.group(3)}", source, count=1)
    updated = NAME.sub(lambda m: f"{m.group(1)}{m.group(2)}{version}{m.group(2)}{m.group(4)}",
                       updated, count=1)
    return VersionPlan(version, code, updated)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", type=Path, default=Path("app/build.gradle"))
    parser.add_argument("--kind", required=True, choices=KINDS)
    parser.add_argument("--expected")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    try:
        result = plan(args.file.read_text(), args.kind, args.expected)
        if args.write:
            args.file.write_text(result.source)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(result.version)

if __name__ == "__main__":
    main()
