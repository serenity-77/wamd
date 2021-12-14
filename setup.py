import os
import glob
from setuptools import setup, find_packages


setup(
    name="wamd",
    author="Harianja Lundu",
    author_email="harianjalundu77@gmail.com",
    package_dir={'': "src"},
    packages=find_packages("src"),
    include_package_data=True,
    install_requires=[
        "twisted",
        "PyOpenSSL",
        "service_identity",
        "autobahn",
        "dissononce",
        "consonance",
        "python-axolotl",
        "protobuf",
        "python-magic",
        "pillow"
    ]
)
