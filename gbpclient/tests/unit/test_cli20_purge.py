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
import errno
import sys

from unittest import mock

from gbpclient.gbp.v2_0 import purge as gbp_purge
from gbpclient.tests.unit import test_cli20
from neutronclient.common import exceptions as n_exc
from neutronclient.neutron.v2_0 import purge


class CLITestV20Purge(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20Purge, self).setUp()
        self.resource_types = ['policy_target', 'policy_target_group',
                               'l2_policy', 'l3_policy', 'external_policy',
                               'nat_pool', 'external_segment',
                               'policy_rule_set', 'policy_rule',
                               'policy_classifier', 'policy_action',
                               'network_service_policy',
                               'application_policy_group']

    def _generate_resources_dict(self, value=0):
        resources_dict = {}
        resources_dict['true'] = value
        for resource_type in self.resource_types:
            resources_dict[resource_type] = value
        return resources_dict

    def _verify_suffix(self, resources, message):
        for resource, value in resources.items():
            if value > 0:
                suffix = list('%(value)d %(resource)s' %
                              {'value': value, 'resource': resource})
                if value != 1:
                    suffix.append('s')
                suffix = ''.join(suffix)
                self.assertIn(suffix, message)
            else:
                self.assertNotIn(resource, message)

    def _verify_message(self, message, deleted, failed):
        message = message.split('.')
        success_prefix = "Deleted "
        failure_prefix = "The following resources could not be deleted: "
        if not deleted['true']:
            for msg in message:
                self.assertNotIn(success_prefix, msg)
            message = message[0]
            if not failed['true']:
                expected = 'Tenant has no supported resources'
                self.assertEqual(expected, message)
            else:
                self.assertIn(failure_prefix, message)
                self._verify_suffix(failed, message)
        else:
            resources_deleted = message[0]
            self.assertIn(success_prefix, resources_deleted)
            self._verify_suffix(deleted, resources_deleted)
            if failed['true']:
                resources_failed = message[1]
                self.assertIn(failure_prefix, resources_failed)
                self._verify_suffix(failed, resources_failed)
            else:
                for msg in message:
                    self.assertNotIn(failure_prefix, msg)

    def _verify_result(self, my_purge, deleted, failed):
        message = my_purge._build_message(deleted, failed, failed['true'])
        self._verify_message(message, deleted, failed)

    def test_build_message(self):
        my_purge = purge.Purge(test_cli20.MyApp(sys.stdout), None)

        # Verify message when tenant has no supported resources
        deleted = self._generate_resources_dict()
        failed = self._generate_resources_dict()
        self._verify_result(my_purge, deleted, failed)

        # Verify message when tenant has supported resources,
        # and they are all deleteable
        deleted = self._generate_resources_dict(1)
        self._verify_result(my_purge, deleted, failed)

        # Verify message when tenant has supported resources,
        # and some are not deleteable
        failed = self._generate_resources_dict(1)
        self._verify_result(my_purge, deleted, failed)

        # Verify message when tenant has supported resources,
        # and all are not deleteable
        deleted = self._generate_resources_dict()
        self._verify_result(my_purge, deleted, failed)


class TestGBPPurge(test_cli20.CLITestV20Base):

    RESOURCE_TYPES = [
        'policy_target', 'policy_target_group', 'l2_policy', 'l3_policy',
        'external_policy', 'nat_pool', 'external_segment', 'policy_rule_set',
        'policy_rule', 'policy_classifier', 'policy_action',
        'network_service_policy', 'application_policy_group']

    def setUp(self):
        super(TestGBPPurge, self).setUp()
        self.purge = gbp_purge.Purge(test_cli20.MyApp(sys.stdout), None)

    def test_pluralize_policy_resource(self):
        self.assertEqual('l2_policies', self.purge._pluralize('l2_policy'))
        self.assertEqual('policy_targets',
                         self.purge._pluralize('policy_target'))

    def test_get_resources_filters_auto_policy_target_groups(self):
        resources = [
            [{'id': 'pt-1'}],
            [{'id': 'auto' + 'a' * 32}, {'id': 'ptg-1'}],
        ]
        self.purge.total_resources = 3
        with mock.patch(
            'neutronclient.neutron.v2_0.purge.Purge.'
            '_get_resources', return_value=resources):
            result = self.purge._get_resources(
                mock.Mock(), ['policy_target', 'policy_target_group'],
                'tenant-id')

        self.assertEqual([[{'id': 'pt-1'}], [{'id': 'ptg-1'}]], result)
        self.assertEqual(2, self.purge.total_resources)

    def test_get_resources_leaves_non_ptg_resources_unchanged(self):
        resources = [[{'id': 'auto' + 'a' * 32}]]
        self.purge.total_resources = 1
        with mock.patch(
            'neutronclient.neutron.v2_0.purge.Purge.'
            '_get_resources', return_value=resources):
            result = self.purge._get_resources(
                mock.Mock(), ['policy_target'], 'tenant-id')

        self.assertEqual(resources, result)
        self.assertEqual(1, self.purge.total_resources)

    def test_purge_resources_counts_deleted_not_found_and_failed(self):
        resources = [[{'id': 'one'}, {'id': 'gone'}, {'id': 'bad'}]]
        self.purge.total_resources = 3
        self.purge.deleted_resources = 0

        def delete_resource(client, resource_type, resource):
            if resource['id'] == 'gone':
                raise n_exc.NotFound(message='missing')
            if resource['id'] == 'bad':
                raise RuntimeError('boom')

        with mock.patch.object(self.purge, '_delete_resource',
                               side_effect=delete_resource), \
                mock.patch('sys.stdout') as stdout:
            deleted, failed, failures = self.purge._purge_resources(
                mock.Mock(), ['policy_target'], resources)

        self.assertTrue(failures)
        self.assertEqual({'policy_target': 2}, deleted)
        self.assertEqual({'policy_target': 1}, failed)
        self.assertEqual(2, self.purge.deleted_resources)
        self.assertEqual(2, self.purge.total_resources)
        self.assertTrue(stdout.write.called)
        self.assertTrue(stdout.flush.called)

    def test_purge_resources_ignores_broken_pipe_progress_write(self):
        resources = [[{'id': 'one'}]]
        self.purge.total_resources = 1
        self.purge.deleted_resources = 0
        broken_pipe = IOError()
        broken_pipe.errno = errno.EPIPE
        with mock.patch.object(self.purge, '_delete_resource'), \
                mock.patch('sys.stdout') as stdout:
            stdout.write.side_effect = broken_pipe
            deleted, failed, failures = self.purge._purge_resources(
                mock.Mock(), ['policy_target'], resources)

        self.assertFalse(failures)
        self.assertEqual({'policy_target': 1}, deleted)
        self.assertEqual({'policy_target': 0}, failed)

    def test_take_action_purges_gbp_then_neutron_resources(self):
        parsed_args = mock.Mock(tenant='tenant-id')
        resources = [[{'id': 'pt-1'}]]
        with mock.patch.object(self.purge, 'get_client',
                               return_value=mock.Mock()) as get_client, \
                mock.patch.object(self.purge, '_get_resources',
                                  return_value=resources) as get_resources, \
                mock.patch.object(self.purge, '_purge_resources',
                                  return_value=({'policy_target': 1},
                                                {'policy_target': 0},
                                                False)) as purge_resources, \
                mock.patch.object(self.purge, '_build_message',
                                  return_value='deleted'), \
                mock.patch('builtins.print') as print_mock, \
                mock.patch(
                    'neutronclient.neutron.v2_0.purge.Purge.take_action',
                    return_value=None) as neutron_take_action:
            self.purge.take_action(parsed_args)

        get_client.assert_called_once_with()
        get_resources.assert_called_once_with(
            get_client.return_value, self.RESOURCE_TYPES, 'tenant-id')
        purge_resources.assert_called_once_with(
            get_client.return_value, self.RESOURCE_TYPES, resources)
        print_mock.assert_called_once_with('\ndeleted')
        neutron_take_action.assert_called_once_with(parsed_args)

    def test_purge_api_returns_injected_client(self):
        client = mock.Mock()
        purge_api = gbp_purge.PurgeAPI(test_cli20.MyApp(sys.stdout), None,
                                       client)
        self.assertEqual(client, purge_api.get_client())
