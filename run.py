#!/usr/bin/env python
# coding: utf-8\
import importlib
import os
import pkgutil

from core.server import run
from hooks import *

for (module_loader, name, splat) in pkgutil.iter_modules([os.path.dirname(__file__)]):
	importlib.import_module('.' + name, __package__)

hooks = [cls() for cls in BaseHook.__subclasses__()]

if __name__ == '__main__':
	run(hooks=hooks)
