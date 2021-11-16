from setuptools import setup, find_packages

setup(
    name="wamd",
    author="Harianja Lundu",
    author_email="harianjalundu77@gmail.com",
    packages=find_packages(),
    install_requires=[
        "twisted",
        "autobahn",
        "dissononce",
        "consonance",
        "python-axolotl",
        "protobuf"
    ],
    include_package_data=True
)
