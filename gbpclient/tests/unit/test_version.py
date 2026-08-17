#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import importlib

from unittest import mock

from oslotest import base

from gbpclient import version


class TestGBPClientVersion(base.BaseTestCase):

    def test_version_uses_package_version_info(self):
        with mock.patch('pbr.version.VersionInfo') as version_info:
            version_info.return_value.version_string.return_value = '1.2.3'
            importlib.reload(version)

        self.assertEqual('1.2.3', version.__version__)
        version_info.assert_called_once_with(
            'python-group-based-policy-client')
        self.addCleanup(importlib.reload, version)
