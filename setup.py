# -*- coding: utf-8 -*-

# Learn more: https://github.com/kennethreitz/setup.py

from setuptools import setup, find_packages


with open('README.rst') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='pcap2sipp',
    version='0.1.0',
    description='pcap2sipp package',
    long_description=readme,
    author='superfast1979',
    author_email='marco.augello@gmail.com',
    url='https://github.com/superfast1979/pcap2sipp',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)
