import os

from setuptools import setup

VERSION = "1.1.2"


def readme():
    """ Load the contents of the README file """
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    with open(readme_path, "r") as f:
        return f.read()


setup(
    name="PoOPassword",
    version=VERSION,
    author="Critizr",
    author_email="master@critizr.com",
    description="A Python library and command line interface for 1Password",
    long_description=readme(),
    install_requires=["pexpect"],
    license="MIT",
    url="https://github.com/critizr/criti-1pass",
    classifiers=[],
    packages=["onepassword"],
)
