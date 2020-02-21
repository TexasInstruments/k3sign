from setuptools import setup, find_packages

setup(
    name="k3sign",
    version="1.0",
    packages=find_packages(),
    python_requires='>3.5',
    install_requires=['cryptography'],
    scripts=['k3sign.py']
)
