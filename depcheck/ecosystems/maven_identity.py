"""Maven package identity shared by static declaration collectors."""

from urllib.parse import quote

from depcheck.model import PackageRef


def package_ref(coordinate: str) -> PackageRef:
    group, separator, artifact = coordinate.partition(":")
    canonical = f"{group}:{artifact}" if separator else coordinate
    purl = None
    if separator and group and artifact:
        purl = f"pkg:maven/{quote(group, safe='.')}/{quote(artifact, safe='-._~')}"
    return PackageRef("Maven", canonical, coordinate, purl)
