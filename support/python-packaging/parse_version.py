from argparse import ArgumentParser
from sys import stdout, stderr


"""
Script to generate a PEP 440 (Post) version from `git-describe` output

== Purpose ==

This script facilitates a form of automatic versioning where the current version is read from its source code
repository, rather than being defined within the project itself. This approach ensures package versions keep in step
with the source repository and are always unique.

Versions are based on the output from `git-describe', itself dependent on Git tags, and formed into a 'PEP 440 (Post)'
complaint version string (e.g. `0.3.0` or `0.3.0.post5.dev0`).

It is expected this script is ran in an environment where file modifications are not persisted, specifically a GitLab
Continuous Integration environment, and that each version string generated is used once, for that environment.

== Usage ==

```
python support/python-packaging/parse_version.py [git describe output] [--pyproject]
```

Where: `[git describe output]` should be replaced by the output of `git describe --tags`. This output can be passed
directly using:

```
python support/python-packaging/parse_version.py $(git describe --tags)
```

The generated version string will be written to *stdout*. If the `--pyproject` flag is set the `tool.poetry.version`
variable in `pyproject.toml` file.

== Implementation ==

Where a commit is a tagged version (e.g. a final release) the version is the same as the tag minus its prefix:

Example input: 'v0.3.0'
Example output: '0.3.0'

Otherwise, the commit will be treated as a post development release for/from the most recent tag plus the distance to
the head commit (e.g. head might be 3 commits ahead of the most recent tag).

Example input:  'v0.3.0-5-g345C2B1'
Example output: '0.3.0.post5.dev0'

The components in this version string are:

* `0.3.0`: the most recent tag/version
* `.post5`: the number of commits since the tag (e.g. 5 commits)
* `.dev0`: signifies a development release (the 0 is a dummy/fixed version prefix)
"""


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('git_describe', help='Output of running `git describe --tags`')
    parser.add_argument('--pyproject', dest='update_pyproject', action='store_true')
    parser.set_defaults(update_pyproject=False)
    args = parser.parse_args()
    error = False

    version_string = ''

    version_elements = str(args.git_describe).split('-')
    if len(version_elements) == 1:
        version_string = version_elements[0].replace('v', '')
    elif len(version_elements) == 3:
        tag = version_elements[0].replace('v', '')
        distance = version_elements[1]
        version_string = f"{tag}.post{distance}.dev0"
    else:
        error = True
        stderr.write('Error: invalid number of elements')
        exit(1)

    if args.update_pyproject:
        from pathlib import Path
        from tomlkit import loads as toml_load, dumps as toml_dump

        pyproject_file_path = Path('./pyproject.toml')

        if pyproject_file_path.exists():
            with open(pyproject_file_path, 'r') as pyproject_file:
                pyproject_contents = pyproject_file.read()

            pyproject_toml = toml_load(pyproject_contents)

            pyproject_toml['tool']['poetry']['version'] = version_string

            with open(pyproject_file_path, 'w') as pyproject_file:
                pyproject_file.write(toml_dump(pyproject_toml))

    stdout.write(version_string)
