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
#

import mock

from gbpclient.gbp.v2_0 import address_scope as address_scope_ext
from gbpclient.tests.unit import test_cli20
from openstackclient.network.v2 import address_scope
from openstackclient.tests.unit.network.v2 import test_address_scope


# Tests for address scope create for APIC extensions
#
class TestAddressScopeCreate(
    test_address_scope.TestAddressScope, test_cli20.CLITestV20Base):

    def setUp(self):
        super(TestAddressScopeCreate, self).setUp()
        self.new_address_scope = (
            test_address_scope.TestCreateAddressScope.new_address_scope)
        self.network.create_address_scope = mock.Mock(
            return_value=self.new_address_scope)

        self.cmd = address_scope.CreateAddressScope(self.app, self.namespace)

    def test_create_default_options(self):
        arglist = [
            test_address_scope.TestCreateAddressScope.new_address_scope.name,
        ]
        verifylist = [
            ('name', self.new_address_scope.name),
            ('apic_distinguished_names', None),
            ('apic_synchronization_state', None),
        ]
        create_ext = address_scope_ext.CreateAndSetAddressScopeExtension(
            self.app)
        parsed_args = self.check_parser_ext(
            self.cmd, arglist, verifylist, create_ext)
        columns, data = self.cmd.take_action(parsed_args)

        self.network.create_address_scope.assert_called_once_with(**{
            'ip_version': self.new_address_scope.ip_version,
            'name': self.new_address_scope.name,
        })

    def test_create_all_options(self):
        arglist = [
            self.new_address_scope.name,
            "--apic-distinguished-names", '{"disttest1": "test1"}',
        ]
        verifylist = [
            ('name', self.new_address_scope.name),
            ('apic_distinguished_names', '{"disttest1": "test1"}'),
            ('apic_synchronization_state', None),
        ]
        create_ext = address_scope_ext.CreateAndSetAddressScopeExtension(
            self.app)
        parsed_args = self.check_parser_ext(
            self.cmd, arglist, verifylist, create_ext)
        columns, data = self.cmd.take_action(parsed_args)

        self.network.create_address_scope.assert_called_once_with(**{
            'ip_version': self.new_address_scope.ip_version,
            'apic:distinguished_names': {"disttest1": "test1"},
            'name': self.new_address_scope.name,
        })


# Tests for address scope set for APIC extensions
#
class TestAddressScopeSet(
    test_address_scope.TestAddressScope, test_cli20.CLITestV20Base):

    _address_scope = test_address_scope.TestSetAddressScope._address_scope

    def setUp(self):
        super(TestAddressScopeSet, self).setUp()
        self.network.update_address_scope = mock.Mock(return_value=None)
        self.network.find_address_scope = mock.Mock(
            return_value=self._address_scope)
        self.cmd = address_scope.SetAddressScope(self.app, self.namespace)

    def test_set_no_options(self):
        arglist = [
            self._address_scope.name,
        ]
        verifylist = [
            ('address_scope', self._address_scope.name),
            ('apic_distinguished_names', None),
            ('apic_synchronization_state', None),
        ]
        set_ext = address_scope_ext.CreateAndSetAddressScopeExtension(self.app)
        parsed_args = self.check_parser_ext(
            self.cmd, arglist, verifylist, set_ext)
        result = self.cmd.take_action(parsed_args)

        attrs = {}
        self.network.update_address_scope.assert_called_with(
            self._address_scope, **attrs)
        self.assertIsNone(result)
