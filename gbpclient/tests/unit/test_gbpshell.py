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

import argparse
import sys

from unittest import mock

from keystoneclient import exceptions as ks_exc
from neutronclient.common import exceptions as n_exc
from oslotest import base

from gbpclient import gbpshell


class TestGBPShellHelpers(base.BaseTestCase):

    def test_run_command_preserves_values_after_double_dash(self):
        cmd = mock.Mock()
        parser = argparse.ArgumentParser()
        parser.add_argument('--flag', action='store_true')

        gbpshell.run_command(cmd, parser, ['--flag', '--', '--tag', 'red'])

        self.assertEqual(['--', '--tag', 'red'], cmd.values_specs)
        cmd.run.assert_called_once_with(mock.ANY)
        self.assertTrue(cmd.run.call_args[0][0].flag)

    def test_run_command_uses_parse_known_args_without_double_dash(self):
        cmd = mock.Mock()
        parser = argparse.ArgumentParser()
        parser.add_argument('--flag', action='store_true')

        gbpshell.run_command(cmd, parser, ['--flag', '--unknown'])

        self.assertEqual(['--unknown'], cmd.values_specs)
        cmd.run.assert_called_once_with(mock.ANY)

    def test_env_returns_first_defined_or_default(self):
        with mock.patch.dict('os.environ', {'SECOND': 'value'}, clear=True):
            self.assertEqual('value', gbpshell.env('FIRST', 'SECOND'))
            self.assertEqual('fallback', gbpshell.env(
                'FIRST', default='fallback'))

    def test_check_non_negative_int(self):
        self.assertEqual(7, gbpshell.check_non_negative_int('7'))
        self.assertRaises(argparse.ArgumentTypeError,
                          gbpshell.check_non_negative_int, '-1')
        self.assertRaises(argparse.ArgumentTypeError,
                          gbpshell.check_non_negative_int, 'bad')


class TestGBPShell(base.BaseTestCase):

    def setUp(self):
        super(TestGBPShell, self).setUp()
        self.shell = gbpshell.GBPShell('2.0')
        self.shell.options = mock.Mock()
        self.shell.options.verbose_level = 0
        self.shell.options.os_auth_strategy = 'keystone'
        self.shell.options.os_token = None
        self.shell.options.os_url = None
        self.shell.options.os_username = 'user'
        self.shell.options.os_user_id = None
        self.shell.options.os_password = 'pass'
        self.shell.options.os_tenant_name = 'tenant'
        self.shell.options.os_tenant_id = None
        self.shell.options.os_project_name = None
        self.shell.options.os_project_domain_name = None
        self.shell.options.os_project_domain_id = None
        self.shell.options.os_project_id = None
        self.shell.options.os_auth_url = 'http://keystone/v3'
        self.shell.options.os_region_name = 'region'
        self.shell.options.os_service_type = 'network'
        self.shell.options.service_type = 'network'
        self.shell.options.os_endpoint_type = 'publicURL'
        self.shell.options.endpoint_type = 'publicURL'
        self.shell.endpoint_type = 'publicURL'
        self.shell.options.insecure = False
        self.shell.options.os_cacert = None
        self.shell.options.http_timeout = None
        self.shell.options.retries = 0
        self.shell.options.os_cert = None
        self.shell.options.os_key = None
        self.shell.options.os_user_domain_name = None
        self.shell.options.os_user_domain_id = None

    def test_build_option_parser_adds_global_options(self):
        parser = self.shell.build_option_parser('description', 'version')
        options = parser.parse_args(['--retries', '2', '--os-url', 'http://n'])
        self.assertEqual(2, options.retries)
        self.assertEqual('http://n', options.os_url)

    def test_bash_completion_prints_commands_and_options(self):
        fake_command = mock.Mock()
        fake_command.get_parser.return_value = argparse.ArgumentParser()
        fake_command.get_parser.return_value.add_argument('--cmd-opt')
        fake_factory = mock.Mock(return_value=fake_command)
        entry_point = mock.Mock()
        entry_point.load.return_value = fake_factory
        self.shell.parser = argparse.ArgumentParser()
        self.shell.parser.add_argument('--global-opt')
        self.shell.command_manager = [('fake-command', entry_point)]
        with mock.patch('builtins.print') as print_mock:
            self.shell._bash_completion()
        output = print_mock.call_args[0][0]
        self.assertIn('fake-command', output)
        self.assertIn('--global-opt', output)
        self.assertIn('--cmd-opt', output)

    def test_run_rewrites_command_help_and_runs_subcommand(self):
        self.shell.parser = mock.Mock()
        self.shell.parser.parse_known_args.return_value = (self.shell.options,
                                                           ['help',
                                                            'group-list'])
        with mock.patch.object(self.shell, 'configure_logging') as configure, \
                mock.patch.object(self.shell, 'initialize_app') as init_app, \
                mock.patch.object(self.shell, 'run_subcommand',
                                  return_value=0) as run_subcommand:
            result = self.shell.run(['group-list', '--help'])

        self.assertEqual(0, result)
        configure.assert_called_once_with()
        init_app.assert_called_once_with(['help', 'group-list'])
        run_subcommand.assert_called_once_with(['help', 'group-list'])

    def test_run_handles_exception_without_debug(self):
        self.shell.options.verbose_level = 0
        self.shell.parser = mock.Mock()
        self.shell.parser.parse_known_args.side_effect = RuntimeError('boom')
        with mock.patch.object(self.shell.log, 'error') as log_error:
            self.assertEqual(1, self.shell.run(['group-list']))
        self.assertTrue(log_error.called)

    def test_run_handles_exception_with_debug_by_reraising(self):
        self.shell.options.verbose_level = self.shell.DEBUG_LEVEL
        self.shell.parser = mock.Mock()
        self.shell.parser.parse_known_args.side_effect = RuntimeError('boom')
        with mock.patch.object(self.shell.log, 'exception'):
            self.assertRaises(RuntimeError, self.shell.run, ['group-list'])

    def test_run_interactive_mode_calls_interact(self):
        self.shell.parser = mock.Mock()
        self.shell.parser.parse_known_args.return_value = (self.shell.options,
                                                           [])
        with mock.patch.object(self.shell, 'configure_logging'), \
                mock.patch.object(self.shell, 'initialize_app'), \
                mock.patch.object(self.shell, 'interact',
                                  return_value=0) as interact, \
                mock.patch('sys.argv', ['gbp', 'extra']):
            self.assertEqual(0, self.shell.run([]))
            self.assertEqual(['gbp'], sys.argv)
        interact.assert_called_once_with()

    def test_run_bash_completion(self):
        with mock.patch.object(self.shell, '_bash_completion',
                               return_value=None) as completion:
            self.assertEqual(0, self.shell.run(['bash-completion']))
        completion.assert_called_once_with()

    def test_run_subcommand_success(self):
        cmd = mock.Mock()
        cmd_parser = mock.Mock()
        cmd.get_parser.return_value = cmd_parser
        factory = mock.Mock(return_value=cmd)
        self.shell.command_manager.find_command = mock.Mock(
            return_value=(factory, 'group-list', ['--arg']))
        self.shell.interactive_mode = False
        self.shell.NAME = 'gbp'
        with mock.patch.object(self.shell,
                               'prepare_to_run_command') as prepare, \
                mock.patch('gbpclient.gbpshell.run_command',
                           return_value=0) as run_command:
            self.assertEqual(0, self.shell.run_subcommand(['group-list']))
        factory.assert_called_once_with(self.shell, self.shell.options)
        prepare.assert_called_once_with(cmd)
        cmd.get_parser.assert_called_once_with('gbp group-list')
        run_command.assert_called_once_with(cmd, cmd_parser, ['--arg'])

    def test_run_subcommand_handles_command_and_cleanup_errors(self):
        cmd = mock.Mock()
        cmd.get_parser.side_effect = RuntimeError('command failed')
        factory = mock.Mock(return_value=cmd)
        self.shell.command_manager.find_command = mock.Mock(
            return_value=(factory, 'group-list', []))
        self.shell.interactive_mode = False
        self.shell.NAME = 'gbp'
        with mock.patch.object(self.shell, 'prepare_to_run_command'), \
                mock.patch.object(self.shell, 'clean_up',
                                  side_effect=RuntimeError(
                                      'cleanup failed')), \
                mock.patch.object(self.shell.log, 'error') as log_error:
            self.assertEqual(1, self.shell.run_subcommand(['group-list']))
        self.assertTrue(log_error.called)

    def test_authenticate_user_rejects_missing_token_url_parts(self):
        self.shell.options.os_token = 'token'
        self.shell.options.os_url = None
        self.assertRaises(n_exc.CommandError, self.shell.authenticate_user)
        self.shell.options.os_token = None
        self.shell.options.os_url = 'http://neutron'
        self.assertRaises(n_exc.CommandError, self.shell.authenticate_user)

    def test_authenticate_user_rejects_missing_password_flow_parts(self):
        self.shell.options.os_username = None
        self.assertRaises(n_exc.CommandError, self.shell.authenticate_user)
        self.shell.options.os_username = 'user'
        self.shell.options.os_password = None
        self.assertRaises(n_exc.CommandError, self.shell.authenticate_user)
        self.shell.options.os_password = 'pass'
        self.shell.options.os_tenant_name = None
        self.assertRaises(n_exc.CommandError, self.shell.authenticate_user)
        self.shell.options.os_tenant_name = 'tenant'
        self.shell.options.os_auth_url = None
        self.assertRaises(n_exc.CommandError, self.shell.authenticate_user)

    def test_authenticate_user_non_keystone_requires_url(self):
        self.shell.options.os_auth_strategy = 'noauth'
        self.shell.options.os_url = None
        self.assertRaises(n_exc.CommandError, self.shell.authenticate_user)

    def test_authenticate_user_builds_client_manager(self):
        auth_session = mock.Mock()
        with mock.patch.object(self.shell, '_get_keystone_session',
                               return_value=auth_session), \
                mock.patch(
                    'gbpclient.gbpshell.clientmanager.'
                    'ClientManager') as manager:
            self.shell.authenticate_user()

        manager.assert_called_once_with(
            token=None, url=None, auth_url='http://keystone/v3',
            tenant_name='tenant', tenant_id=None, username='user',
            user_id=None, password='pass', region_name='region',
            api_version='2.0', auth_strategy='keystone',
            service_type='network', endpoint_type='publicURL', insecure=False,
            ca_cert=None, timeout=None, retries=0, raise_errors=False,
            session=auth_session, auth=auth_session.auth,
            log_credentials=True)

    def test_initialize_app_authenticates_unless_help_command(self):
        self.shell.interactive_mode = False
        self.shell.command_manager.find_command = mock.Mock(
            return_value=(mock.Mock(), 'group-list', []))
        with mock.patch('cliff.app.App.initialize_app'), \
                mock.patch.object(self.shell, 'authenticate_user') as auth:
            self.shell.initialize_app(['group-list'])
        auth.assert_called_once_with()

        self.shell.command_manager.find_command.return_value = (
            mock.Mock(), 'help', [])
        with mock.patch('cliff.app.App.initialize_app'), \
                mock.patch.object(self.shell, 'authenticate_user') as auth:
            self.shell.initialize_app(['help'])
        auth.assert_not_called()

    def test_get_v2_and_v3_auth(self):
        with mock.patch('gbpclient.gbpshell.v2_auth.Password') as v2_password:
            self.assertEqual(v2_password.return_value,
                             self.shell.get_v2_auth('http://keystone/v2.0'))
        with mock.patch('gbpclient.gbpshell.v3_auth.Password') as v3_password:
            self.assertEqual(v3_password.return_value,
                             self.shell.get_v3_auth('http://keystone/v3'))

    def test_discover_auth_versions_uses_discovery(self):
        discover = mock.Mock()
        discover.url_for.side_effect = ['http://v2', 'http://v3']
        with mock.patch('gbpclient.gbpshell.discover.Discover',
                        return_value=discover):
            self.assertEqual(('http://v2', 'http://v3'),
                             self.shell._discover_auth_versions(
                                 mock.Mock(), 'http://keystone'))

    def test_discover_auth_versions_falls_back_to_url_path(self):
        with mock.patch('gbpclient.gbpshell.discover.Discover',
                        side_effect=ks_exc.ClientException()):
            self.assertEqual((None, 'http://host/v3'),
                             self.shell._discover_auth_versions(
                                 mock.Mock(), 'http://host/v3'))
            self.assertEqual(('http://host/v2.0', None),
                             self.shell._discover_auth_versions(
                                 mock.Mock(), 'http://host/v2.0'))
            self.assertRaises(n_exc.CommandError,
                              self.shell._discover_auth_versions,
                              mock.Mock(), 'http://host/identity')

    def test_get_keystone_session_selects_v2_or_v3(self):
        session = mock.Mock()
        with mock.patch('gbpclient.gbpshell.session.Session.construct',
                        return_value=session), \
                mock.patch.object(self.shell, '_discover_auth_versions',
                                  return_value=('http://v2', 'http://v3')), \
                mock.patch.object(self.shell, 'get_v2_auth',
                                  return_value='v2-auth') as get_v2:
            self.assertEqual(session, self.shell._get_keystone_session())
        get_v2.assert_called_once_with('http://v2')
        self.assertEqual('v2-auth', session.auth)

        self.shell.options.os_user_domain_name = 'Default'
        with mock.patch('gbpclient.gbpshell.session.Session.construct',
                        return_value=session), \
                mock.patch.object(self.shell, '_discover_auth_versions',
                                  return_value=('http://v2', 'http://v3')), \
                mock.patch.object(self.shell, 'get_v3_auth',
                                  return_value='v3-auth') as get_v3:
            self.assertEqual(session, self.shell._get_keystone_session())
        get_v3.assert_called_once_with('http://v3')
        self.assertEqual('v3-auth', session.auth)

    def test_main_returns_status_for_known_exceptions(self):
        with mock.patch('gbpclient.gbpshell.GBPShell') as shell_cls:
            shell_cls.return_value.run.side_effect = (
                n_exc.NeutronClientException)
            self.assertEqual(1, gbpshell.main(['group-list']))
        with mock.patch('gbpclient.gbpshell.GBPShell') as shell_cls, \
                mock.patch('builtins.print') as print_mock:
            shell_cls.return_value.run.side_effect = RuntimeError('boom')
            self.assertEqual(1, gbpshell.main(['group-list']))
        print_mock.assert_called_once_with('boom')
