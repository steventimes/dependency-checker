"""C/C++ package and build declaration evidence."""

from .collector import create_conan_pack, create_vcpkg_pack

__all__ = ["create_conan_pack", "create_vcpkg_pack"]
