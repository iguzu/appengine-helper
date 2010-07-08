#!/usr/bin/python2.4
#
# Copyright 2009 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Replacement YAML dumper that can handle datetime.time objects.
"""

import datetime
import yaml

try:
    import decimal
except ImportError:
    from django.utils import _decimal as decimal # Python 2.3 fallback


class DjangoSafeDumper(yaml.SafeDumper):
    """Replacement DjangoSafeDumper that handles datetime.time objects.

    Serializes datetime.time objects to a YAML timestamp tag, there is a
    corresponding hack in python.py to convert the datetime.datetime that the
    YAML decoder returns back to the expected datetime.time object.
    """

    def represent_decimal(self, data):
        return self.represent_scalar('tag:yaml.org,2002:str', str(data))

    def represent_time(self, data):
        value = '1970-01-01 %s' % unicode(data.isoformat())
        return self.represent_scalar('tag:yaml.org,2002:timestamp', value)

DjangoSafeDumper.add_representer(decimal.Decimal, DjangoSafeDumper.represent_decimal)
DjangoSafeDumper.add_representer(datetime.time, DjangoSafeDumper.represent_time)
