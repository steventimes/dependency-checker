# Description

This is a lightweight program that detects:

1. Unused imports
2. Missing dependencies
3. Package secure issue (using OSV API)

## How to Run

To run from source code: `python main.py <path>`

To run as a module: `python -m depcheck {folder to scan}`

## Option

`--json` to return output in json format

## Workflow of the program

The program will scan through all python files to find used imports, and then compare to *requirement.txt*. And for all imports, it will send to OSV API to check for vulnerabilities.

### Future of this little project

1. try on auto fixing unused imports
2. recommand a list of packages with their version to fix the vulnerability
3. write documentations
