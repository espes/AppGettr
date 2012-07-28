from setuptools import setup

import sys
if 'py2exe' in sys.argv:
	import py2exe

	setup(
		name = "AppGettr",
		version = "0.23",
		author = "espes",
		install_requires = ["pycrypto", "biplist", "progressbar", "BeautifulSoup"],
		options = {'py2exe': {'bundle_files': 1, 'optimize': 2}},
		console = [{
		  "script": "AppGettr.py"
		}],
		zipfile = None,
	)
else:
	setup(
		name = "AppGettr",
		version = "0.23",
		author = "espes",
		install_requires = ["pycrypto", "biplist", "progressbar", "BeautifulSoup"],
		scripts=['AppGettr.py'],
	)
