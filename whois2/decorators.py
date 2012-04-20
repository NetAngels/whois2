# -*- coding: utf-8 -*-
"""
Registrar decorator can be used to add objects (function and classes) to the
registry.

>>> reg = Registrar()
>>> @reg('foo')
... def foo():
...     print 'foo'
...
>>> @reg('bar')
... def bar():
...     print 'bar'
...
>>> reg.registry
{'foo': <function foo at 0x...>, 'bar': <function bar at 0x...>}
>>> reg.registry['foo']()
foo
>>> reg.registry['bar']()
bar
"""
from collections import defaultdict


class Registrar(object):

    def __init__(self):
        self.registry = defaultdict(lambda: [])

    def __call__(self, *keys):
        def wrapper(obj):
            for key in keys:
                self.registry[key].append(obj)
            return obj
        return wrapper

    def get(self, key):
        return self.registry['__all__'] + self.registry[key]

    def get_keys(self):
        keys = self.registry.keys()
        if '__all__' in keys:
            keys.remove('__all__')
        return keys
