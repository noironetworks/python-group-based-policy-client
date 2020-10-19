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
Subnet extension implementations
"""

from oslo_serialization import jsonutils

from cliff import hooks
from openstack.network.v2 import subnet as subnet_sdk
from openstack import resource
from openstackclient.network.v2 import subnet

from openstackclient.i18n import _


_get_attrs_subnet_new = subnet._get_attrs


def _get_attrs_subnet_extension(client_manager, parsed_args, is_create=True):
    attrs = _get_attrs_subnet_new(client_manager, parsed_args, is_create)
    if parsed_args.apic_distinguished_names:
        attrs['apic:distinguished_names'
              ] = jsonutils.loads(parsed_args.apic_distinguished_names)
    if parsed_args.apic_synchronization_state:
        attrs['apic:synchronization_state'
              ] = parsed_args.apic_synchronization_state
    if parsed_args.apic_snat_host_pool_enable:
        attrs['apic:snat_host_pool'] = True
    if parsed_args.apic_snat_host_pool_disable:
        attrs['apic:snat_host_pool'] = False
    if parsed_args.apic_active_active_aap_enable:
        attrs['apic:active_active_aap'] = True
    if parsed_args.apic_active_active_aap_disable:
        attrs['apic:active_active_aap'] = False
    return attrs


subnet._get_attrs = _get_attrs_subnet_extension

subnet_sdk.Subnet.apic_distinguished_names = resource.Body(
    'apic:distinguished_names')
subnet_sdk.Subnet.apic_synchronization_state = resource.Body(
    'apic:synchronization_state')
subnet_sdk.Subnet.apic_snat_host_pool = resource.Body(
    'apic:snat_host_pool')
subnet_sdk.Subnet.apic_active_active_aap = resource.Body(
    'apic:active_active_aap')


class CreateAndSetSubnetExtension(hooks.CommandHook):

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
        parser.add_argument(
            '--apic-snat-host-pool-enable',
            action='store_true',
            default=None,
            dest='apic_snat_host_pool_enable',
            help=_("Set Apic snat host pool to true")
        )
        parser.add_argument(
            '--apic-snat-host-pool-disable',
            action='store_true',
            dest='apic_snat_host_pool_disable',
            help=_("Set Apic snat host pool to false")
        )
        parser.add_argument(
            '--apic-active-active-aap-enable',
            action='store_true',
            default=None,
            dest='apic_active_active_aap_enable',
            help=_("Set Apic active active aap to true")
        )
        parser.add_argument(
            '--apic-active-active-aap-disable',
            action='store_true',
            dest='apic_active_active_aap_disable',
            help=_("Set Apic active active aap to false")
        )
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code


class ShowSubnetExtension(hooks.CommandHook):

    def get_parser(self, parser):
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code
