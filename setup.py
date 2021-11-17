from setuptools import setup, find_packages

setup(
    name="wamd",
    author="Harianja Lundu",
    author_email="harianjalundu77@gmail.com",
    packages=find_packages(),
    install_requires=[
        "twisted",
        "PyOpenSSL",
        "service_identity",
        "autobahn",
        "dissononce",
        "consonance",
        "python-axolotl",
        "protobuf",
        "setuptools-rust"
    ],
    include_package_data=True
)
