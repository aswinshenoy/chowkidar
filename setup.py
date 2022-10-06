import os
from setuptools import setup

README = open(os.path.join(os.path.dirname(__file__), 'README.md'), encoding='utf8').read()

# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup()
