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
Network extension implementations
"""

import ast

from oslo_serialization import jsonutils

from cliff import hooks
from openstack.network.v2 import network as network_sdk
from openstack import resource
from openstackclient.network.v2 import network

from openstackclient.i18n import _


_get_attrs_network_new = network._get_attrs_network


def _get_attrs_network_extension(client_manager, parsed_args):
    attrs = _get_attrs_network_new(client_manager, parsed_args)
    if parsed_args.apic_synchronization_state:
        attrs['apic:synchronization_state'
              ] = parsed_args.apic_synchronization_state
    if parsed_args.apic_svi_enable:
        attrs['apic:svi'] = True
    if parsed_args.apic_svi_disable:
        attrs['apic:svi'] = False
    if parsed_args.apic_bgp_enable:
        attrs['apic:bgp_enable'] = True
    if parsed_args.apic_bgp_disable:
        attrs['apic:bgp_enable'] = False
    if parsed_args.apic_bgp_type:
        attrs['apic:bgp_type'] = parsed_args.apic_bgp_type
    if parsed_args.apic_bgp_asn:
        attrs['apic:bgp_asn'] = parsed_args.apic_bgp_asn
    if parsed_args.apic_nested_domain_name:
        attrs['apic:nested_domain_name'
              ] = parsed_args.apic_nested_domain_name
    if parsed_args.apic_nested_domain_type:
        attrs['apic:nested_domain_type'
              ] = parsed_args.apic_nested_domain_type
    if parsed_args.apic_nested_domain_infra_vlan:
        attrs['apic:nested_domain_infra_vlan'
              ] = parsed_args.apic_nested_domain_infra_vlan
    if parsed_args.apic_nested_domain_service_vlan:
        attrs['apic:nested_domain_service_vlan'
              ] = parsed_args.apic_nested_domain_service_vlan
    if parsed_args.apic_nested_domain_node_network_vlan:
        attrs['apic:nested_domain_node_network_vlan'
              ] = parsed_args.apic_nested_domain_node_network_vlan
    if parsed_args.apic_nested_domain_allowed_vlans:
        attrs['apic:nested_domain_allowed_vlans'
              ] = ast.literal_eval(
                  parsed_args.apic_nested_domain_allowed_vlans)
    if parsed_args.apic_extra_provided_contracts:
        attrs['apic:extra_provided_contracts'
              ] = ast.literal_eval(parsed_args.apic_extra_provided_contracts)
    if parsed_args.apic_extra_consumed_contracts:
        attrs['apic:extra_consumed_contracts'
              ] = ast.literal_eval(parsed_args.apic_extra_consumed_contracts)
    if parsed_args.apic_epg_contract_masters:
        attrs['apic:epg_contract_masters'
              ] = ast.literal_eval(parsed_args.apic_epg_contract_masters)
    if parsed_args.apic_distinguished_names:
        attrs['apic:distinguished_names'
              ] = jsonutils.loads(parsed_args.apic_distinguished_names)
    if parsed_args.external:
        if parsed_args.apic_nat_type:
            attrs['apic:nat_type'] = parsed_args.apic_nat_type
        if parsed_args.apic_external_cidrs:
            attrs['apic:external_cidrs'
                  ] = ast.literal_eval(parsed_args.apic_external_cidrs)
    return attrs


network._get_attrs_network = _get_attrs_network_extension

network_sdk.Network.apic_synchronization_state = resource.Body(
    'apic:synchronization_state')
network_sdk.Network.apic_svi = resource.Body('apic:svi')
network_sdk.Network.apic_bgp = resource.Body('apic:bgp_enable')
network_sdk.Network.apic_bgp_type = resource.Body('apic:bgp_type')
network_sdk.Network.apic_bgp_asn = resource.Body('apic:bgp_asn')
network_sdk.Network.apic_nested_domain_name = resource.Body(
    'apic:nested_domain_name')
network_sdk.Network.apic_nested_domain_type = resource.Body(
    'apic:nested_domain_type')
network_sdk.Network.apic_nested_domain_infra_vlan = resource.Body(
    'apic:nested_domain_infra_vlan')
network_sdk.Network.apic_nested_domain_service_vlan = resource.Body(
    'apic:nested_domain_service_vlan')
network_sdk.Network.apic_nested_domain_node_network_vlan = resource.Body(
    'apic:nested_domain_node_network_vlan')
network_sdk.Network.apic_nested_domain_allowed_vlans = resource.Body(
    'apic:nested_domain_allowed_vlans')
network_sdk.Network.apic_extra_provided_contracts = resource.Body(
    'apic:extra_provided_contracts')
network_sdk.Network.apic_extra_consumed_contracts = resource.Body(
    'apic:extra_consumed_contracts')
network_sdk.Network.apic_epg_contract_masters = resource.Body(
    'apic:epg_contract_masters')
network_sdk.Network.apic_distinguished_names = resource.Body(
    'apic:distinguished_names')
network_sdk.Network.apic_nat_type = resource.Body('apic:nat_type')
network_sdk.Network.apic_external_cidrs = resource.Body('apic:external_cidrs')


class CreateAndSetNetworkExtension(hooks.CommandHook):

    def get_parser(self, parser):
        parser.add_argument(
            '--apic-synchronization-state',
            metavar="<apic_synchronization_state>",
            dest='apic_synchronization_state',
            help=_("Apic synchronization state")
        )
        parser.add_argument(
            '--apic-svi-enable',
            action='store_true',
            default=None,
            dest='apic_svi_enable',
            help=_("Set Apic SVI to true")
        )
        parser.add_argument(
            '--apic-svi-disable',
            action='store_true',
            dest='apic_svi_disable',
            help=_("Set Apic SVI to false")
        )
        parser.add_argument(
            '--apic-bgp-enable',
            action='store_true',
            default=None,
            dest='apic_bgp_enable',
            help=_("Set Apic BGP to true")
        )
        parser.add_argument(
            '--apic-bgp-disable',
            action='store_true',
            dest='apic_bgp_disable',
            help=_("Set Apic BGP to false")
        )
        parser.add_argument(
            '--apic-bgp-type',
            metavar="<apic_bgp_type>",
            dest='apic_bgp_type',
            help=_("Apic BGP Type")
        )
        parser.add_argument(
            '--apic-bgp-asn',
            metavar="<apic_bgp_asn>",
            dest='apic_bgp_asn',
            help=_("Apic BGP ASN")
        )
        parser.add_argument(
            '--apic-nested-domain-name',
            metavar="<apic_nested_domain_name>",
            dest='apic_nested_domain_name',
            help=_("Apic nested domain name")
        )
        parser.add_argument(
            '--apic-nested-domain-type',
            metavar="<apic_nested_domain_type>",
            dest='apic_nested_domain_type',
            help=_("Apic nested domain type")
        )
        parser.add_argument(
            '--apic-nested-domain-infra-vlan',
            metavar="<apic_nested_domain_infra_vlan>",
            dest='apic_nested_domain_infra_vlan',
            help=_("Apic nested domain infra vlan")
        )
        parser.add_argument(
            '--apic-nested-domain-service-vlan',
            metavar="<apic_nested_domain_service_vlan>",
            dest='apic_nested_domain_service_vlan',
            help=_("Apic nested domain service vlan")
        )
        parser.add_argument(
            '--apic-nested-domain-node-network-vlan',
            metavar="<apic_nested_domain_node_network_vlan>",
            dest='apic_nested_domain_node_network_vlan',
            help=_("Apic nested domain node network vlan")
        )
        parser.add_argument(
            '--apic-nested-domain-allowed-vlans',
            metavar="<apic_nested_domain_allowed_vlans>",
            dest='apic_nested_domain_allowed_vlans',
            help=_("Apic nested domain allowed vlans")
        )
        parser.add_argument(
            '--apic-extra-provided-contracts',
            metavar="<apic_extra_provided_contracts>",
            dest='apic_extra_provided_contracts',
            help=_("Apic extra provided contracts")
        )
        parser.add_argument(
            '--apic-extra-consumed-contracts',
            metavar="<apic_extra_consumed_contracts>",
            dest='apic_extra_consumed_contracts',
            help=_("Apic extra consumed contracts")
        )
        parser.add_argument(
            '--apic-epg-contract-masters',
            metavar="<apic_epg_contract_masters>",
            dest='apic_epg_contract_masters',
            help=_("Apic epg contract masters")
        )
        parser.add_argument(
            '--apic-distinguished-names',
            metavar="<apic_distinguished_names>",
            dest='apic_distinguished_names',
            help=_("Apic distinguished names")
        )
        parser.add_argument(
            '--apic-nat-type',
            metavar="<apic_nat_type>",
            dest='apic_nat_type',
            help=_("Apic nat type for external network")
        )
        parser.add_argument(
            '--apic-external-cidrs',
            metavar="<apic_external_cidrs>",
            dest='apic_external_cidrs',
            help=_("Apic external CIDRS for external network")
        )
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code


class ShowNetworkExtension(hooks.CommandHook):

    def get_parser(self, parser):
        return parser

    def get_epilog(self):
        return ''

    def before(self, parsed_args):
        return parsed_args

    def after(self, parsed_args, return_code):
        return return_code
