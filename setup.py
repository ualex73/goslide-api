'''
Install Slide Open Cloud and Local API
'''

import setuptools

with open('README.pypi') as f:
    LONG_DESCRIPTION = f.read()

setuptools.setup(
    name='goslide-api',
    version='0.7.3',
    url='https://github.com/ualex73/goslide-api',
    license='Apache License 2.0',
    author='Alexander Kuiper',
    author_email='ualex73@gmail.com',
    description='Python API to utilise the Slide Open Cloud and Local API',
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    install_requires=['aiohttp'],
    python_requires='>=3.5.2',
    classifiers=[
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
)
