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

"""
Address Scope extension implementations
"""

from oslo_serialization import jsonutils

from cliff import hooks
from openstack.network.v2 import address_scope as address_scope_sdk
from openstack import resource
from openstackclient.network.v2 import address_scope

from openstackclient.i18n import _


_get_attrs_address_scope_new = address_scope._get_attrs


def _get_attrs_address_scope_extension(client_manager, parsed_args):
    attrs = _get_attrs_address_scope_new(client_manager, parsed_args)
    if parsed_args.apic_distinguished_names:
        attrs['apic:distinguished_names'
              ] = jsonutils.loads(parsed_args.apic_distinguished_names)
    if parsed_args.apic_synchronization_state:
        attrs['apic:synchronization_state'
              ] = parsed_args.apic_synchronization_state
    return attrs


address_scope._get_attrs = _get_attrs_address_scope_extension

address_scope_sdk.AddressScope.apic_distinguished_names = resource.Body(
    'apic:distinguished_names')
address_scope_sdk.AddressScope.apic_synchronization_state = resource.Body(
    'apic:synchronization_state')


class CreateAndSetAddressScopeExtension(hooks.CommandHook):

    def get_parser(self, parser):
        parser.add_argument(
            '--apic-distinguished-names',
            metavar="<apic_distinguished_names>",
            dest='apic_distinguished_names',
            help=_("Apic distinguished names")
        )
        parser.add_argument(
            '--apic-synchronization-state',
            metavar="<apic_synchronization_state>",
            dest='apic_synchronization_state',
            help=_("Apic synchronization state")
        )
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code


class ShowAddressScopeExtension(hooks.CommandHook):

    def get_parser(self, parser):
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code
