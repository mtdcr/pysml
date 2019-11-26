#!/usr/bin/env python

from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='pysml',
    version='0.0.2',
    author='Andreas Oberritter',
    author_email='obi@saftware.de',
    url='https://github.com/mtdcr/pysml',
    description='Library for EDL21 smart meters using Smart Message Language (SML)',
    download_url='https://github.com/mtdcr/pysml',
    license='MIT',
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=['sml'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Home Automation',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    install_requires=[
        'async-timeout>=3.0.1',
        'bitstring>=3.1.5',
        'pyserial-asyncio>=0.4',
    ],
)
