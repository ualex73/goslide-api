'''
Install goslide.io Open Cloud API
'''

import setuptools

with open('README.md') as f:
    LONG_DESCRIPTION = f.read()

setuptools.setup(
    name='goslide-api',
    version='0.0.2',
    url='https://github.com/ualex73/goslide-api',
    license='Apache License 2.0',
    author='Alexander Kuiper',
    author_email='ualex73@gmail.com',
    description='Python API to utilise the goslide.io Open Cloud API',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    install_requires=['aiohttp', 'asyncio'],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
)
