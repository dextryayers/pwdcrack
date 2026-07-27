"""Python wrapper for pwdcrack Rust core."""

from setuptools import setup

# This is placeholder. Actual build uses maturin for PyO3 bindings.
# See: https://github.com/PyO3/maturin

setup(
    name="pwdcrack",
    version="0.1.0",
    description="Python bindings for pwdcrack — universal password cracker",
    packages=["pwdcrack"],
    package_data={"pwdcrack": ["*.so", "*.dll", "*.dylib"]},
    include_package_data=True,
)
