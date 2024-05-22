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

import contextlib
from io import StringIO
import itertools
import sys
from unittest import mock
import urllib.parse as urlparse

import fixtures
from oslo_utils import encodeutils
from oslotest import base
import requests

from gbpclient import gbpshell as shell
from gbpclient.v2_0 import client
from neutronclient.common import constants
from neutronclient.common import exceptions
from neutronclient.tests.unit import test_http

API_VERSION = "2.0"
TOKEN = test_http.AUTH_TOKEN
ENDURL = test_http.END_URL
REQUEST_ID = 'test_request_id'


@contextlib.contextmanager
def capture_std_streams():
    fake_stdout, fake_stderr = StringIO(), StringIO()
    stdout, stderr = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = fake_stdout, fake_stderr
        yield fake_stdout, fake_stderr
    finally:
        sys.stdout, sys.stderr = stdout, stderr


class ParserException(Exception):
    pass


class FakeStdout(object):

    def __init__(self):
        self.content = []

    def write(self, text):
        self.content.append(text)

    def make_string(self):
        result = ''
        for line in self.content:
            result += encodeutils.safe_decode(line, 'utf-8')
        return result


class MyRequest(requests.Request):
    def __init__(self, method=None):
        self.method = method


class MyResp(requests.Response):
    def __init__(self, status_code, headers=None, reason=None,
                 request=None, url=None):
        self.status_code = status_code
        self.headers = headers or {}
        self.reason = reason
        self.request = request or MyRequest()
        self.url = url


class MyApp(object):
    def __init__(self, _stdout):
        self.stdout = _stdout


def end_url(path, query=None):
    _url_str = ENDURL + "/v" + API_VERSION + path
    return query and _url_str + "?" + query or _url_str


class MyUrlComparator(object):
    def __init__(self, lhs, client):
        self.lhs = lhs
        self.client = client

    def __eq__(self, rhs):
        lhsp = urlparse.urlparse(self.lhs)
        rhsp = urlparse.urlparse(rhs)

        lhs_qs = urlparse.parse_qsl(lhsp.query)
        rhs_qs = urlparse.parse_qsl(rhsp.query)

        return (lhsp.scheme == rhsp.scheme and
                lhsp.netloc == rhsp.netloc and
                lhsp.path == rhsp.path and
                len(lhs_qs) == len(rhs_qs) and
                set(lhs_qs) == set(rhs_qs))

    def __str__(self):
        return self.lhs

    def __repr__(self):
        return str(self)


class MyComparator(object):
    def __init__(self, lhs, client):
        self.lhs = lhs
        self.client = client

    def _com_dict(self, lhs, rhs):
        if len(lhs) != len(rhs):
            return False
        for key, value in lhs.items():
            if key not in rhs:
                return False
            rhs_value = rhs[key]
            if not self._com(value, rhs_value):
                return False
        return True

    def _com_list(self, lhs, rhs):
        if len(lhs) != len(rhs):
            return False
        for lhs_value in lhs:
            if lhs_value not in rhs:
                return False
        return True

    def _com(self, lhs, rhs):
        if lhs is None:
            return rhs is None
        if isinstance(lhs, dict):
            if not isinstance(rhs, dict):
                return False
            return self._com_dict(lhs, rhs)
        if isinstance(lhs, list):
            if not isinstance(rhs, list):
                return False
            return self._com_list(lhs, rhs)
        if isinstance(lhs, tuple):
            if not isinstance(rhs, tuple):
                return False
            return self._com_list(lhs, rhs)
        return lhs == rhs

    def __eq__(self, rhs):
        if self.client:
            rhs = self.client.deserialize(rhs, 200)
        return self._com(self.lhs, rhs)

    def __repr__(self):
        if self.client:
            return self.client.serialize(self.lhs)
        return str(self.lhs)


class ContainsKeyValue(object):
    """Checks whether key/value pair(s) are included in a dict parameter.

    This class just checks whether specifid key/value pairs passed in
    __init__() are included in a dict parameter. The comparison does not
    fail even if other key/value pair(s) exists in a target dict.
    """

    def __init__(self, expected):
        self._expected = expected

    def __eq__(self, other):
        if not isinstance(other, dict):
            return False
        for key, value in self._expected.items():
            if key not in other:
                return False
            if other[key] != value:
                return False
        return True

    def __repr__(self):
        return ('<%s (expected: %s)>' %
                (self.__class__.__name__, self._expected))


class IsA(object):
    """Checks whether the parameter is of specific type."""

    def __init__(self, expected_type):
        self._expected_type = expected_type

    def __eq__(self, other):
        return isinstance(other, self._expected_type)

    def __repr__(self):
        return ('<%s (expected: %s)>' %
                (self.__class__.__name__, self._expected_type))


class CLITestV20Base(base.BaseTestCase):

    test_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
    id_field = 'id'

    non_admin_status_resources = []

    def _find_resourceid(self, client, resource, name_or_id,
                         cmd_resource=None, parent_id=None):
        return name_or_id

    def setUp(self, plurals=None):
        """Prepare the test environment."""
        super(CLITestV20Base, self).setUp()
        client.Client.EXTED_PLURALS.update(constants.PLURALS)
        if plurals is not None:
            client.Client.EXTED_PLURALS.update(plurals)
        self.metadata = {'plurals': client.Client.EXTED_PLURALS}
        self.endurl = ENDURL
        self.fake_stdout = FakeStdout()

        self.addCleanup(mock.patch.stopall)
        mock.patch('sys.stdout', new=self.fake_stdout).start()
        mock.patch('neutronclient.neutron.v2_0.find_resourceid_by_name_or_id',
                   new=self._find_resourceid).start()
        mock.patch('neutronclient.neutron.v2_0.find_resourceid_by_id',
                   new=self._find_resourceid).start()

        self.client = client.Client(token=TOKEN, endpoint_url=self.endurl)

    def register_non_admin_status_resource(self, resource_name):
        # TODO(amotoki):
        # It is recommended to define
        # "non_admin_status_resources in each test class rather than
        # using register_non_admin_status_resource method.

        # If we change self.non_admin_status_resources like this,
        # we need to ensure this should be an instance variable
        # to avoid changing the class variable.
        if (id(self.non_admin_status_resources) ==
                id(self.__class__.non_admin_status_resources)):
            self.non_admin_status_resources = (self.__class__.
                                               non_admin_status_resources[:])
        self.non_admin_status_resources.append(resource_name)

    def _test_create_resource(self, resource, cmd, name, myid, args,
                              position_names, position_values,
                              tenant_id=None, tags=None, admin_state_up=True,
                              extra_body=None, cmd_resource=None,
                              parent_id=None, **kwargs):
        if not cmd_resource:
            cmd_resource = resource
        body = {resource: {}, }
        if tenant_id:
            body[resource].update({'tenant_id': tenant_id})
        if tags:
            body[resource].update({'tags': tags})
        if extra_body:
            body[resource].update(extra_body)
        body[resource].update(kwargs)

        for i in range(len(position_names)):
            body[resource].update({position_names[i]: position_values[i]})
        ress = {resource:
                {self.id_field: myid}, }
        if name:
            ress[resource].update({'name': name})
        resstr = self.client.serialize(ress)
        # url method body
        resource_plural = self.client.get_resource_plural(cmd_resource)
        path = getattr(self.client, resource_plural + "_path")
        if parent_id:
            path = path % parent_id
        mock_body = MyComparator(body, self.client)
        cmd_parser = cmd.get_parser('create_' + resource)
        resp = (MyResp(200), resstr)

        with mock.patch.object(
            cmd, "get_client", return_value=self.client
        ) as mock_get_client, mock.patch.object(
            self.client.httpclient, "request", return_value=resp
        ) as mock_request:
            shell.run_command(cmd, cmd_parser, args)

            self.assert_mock_multiple_calls_with_same_arguments(
                mock_get_client, mock.call(), None)

            mock_request.assert_called_once_with(
                end_url(path), 'POST',
                body=mock_body,
                headers=ContainsKeyValue(
                    {'X-Auth-Token': TOKEN}))

        _str = self.fake_stdout.make_string()
        self.assertIn(myid, _str)
        if name:
            self.assertIn(name, _str)

    def _test_list_resources(self, resources, cmd, detail=False, tags=(),
                             fields_1=(), fields_2=(), page_size=None,
                             sort_key=(), sort_dir=(), response_contents=None,
                             base_args=None, path=None, cmd_resources=None,
                             parent_id=None, output_format=None, query=""):
        if not cmd_resources:
            cmd_resources = resources
        if response_contents is None:
            contents = [{self.id_field: 'myid1', },
                        {self.id_field: 'myid2', }, ]
        else:
            contents = response_contents
        reses = {resources: contents}
        resstr = self.client.serialize(reses)
        # url method body
        args = base_args if base_args is not None else []
        if detail:
            args.append('-D')
        if fields_1:
            for field in fields_1:
                args.append('--fields')
                args.append(field)

        if tags:
            args.append('--')
            args.append("--tag")
        for tag in tags:
            args.append(tag)
            tag_query = urlparse.urlencode(
                {'tag': encodeutils.safe_encode(tag)})
            if query:
                query += "&" + tag_query
            else:
                query = tag_query
        if (not tags) and fields_2:
            args.append('--')
        if fields_2:
            args.append("--fields")
            for field in fields_2:
                args.append(field)
        if detail:
            query = query and query + '&verbose=True' or 'verbose=True'
        for field in itertools.chain(fields_1, fields_2):
            if query:
                query += "&fields=" + field
            else:
                query = "fields=" + field
        if page_size:
            args.append("--page-size")
            args.append(str(page_size))
            if query:
                query += "&limit=%s" % page_size
            else:
                query = "limit=%s" % page_size
        if sort_key:
            for key in sort_key:
                args.append('--sort-key')
                args.append(key)
                if query:
                    query += '&'
                query += 'sort_key=%s' % key
        if sort_dir:
            len_diff = len(sort_key) - len(sort_dir)
            if len_diff > 0:
                sort_dir = tuple(sort_dir) + ('asc',) * len_diff
            elif len_diff < 0:
                sort_dir = sort_dir[:len(sort_key)]
            for dir in sort_dir:
                args.append('--sort-dir')
                args.append(dir)
                if query:
                    query += '&'
                query += 'sort_dir=%s' % dir
        if path is None:
            path = getattr(self.client, cmd_resources + "_path")
            if parent_id:
                path = path % parent_id
        if output_format:
            args.append('-f')
            args.append(output_format)
        cmd_parser = cmd.get_parser("list_" + cmd_resources)
        resp = (MyResp(200), resstr)

        with mock.patch.object(cmd, "get_client",
                               return_value=self.client) as mock_get_client, \
                mock.patch.object(self.client.httpclient, "request",
                                  return_value=resp) as mock_request:
            shell.run_command(cmd, cmd_parser, args)

        self.assert_mock_multiple_calls_with_same_arguments(
            mock_get_client, mock.call(), None)
        mock_request.assert_called_once_with(
            MyUrlComparator(end_url(path, query), self.client),
            'GET',
            body=None,
            headers=ContainsKeyValue({'X-Auth-Token': TOKEN}))
        _str = self.fake_stdout.make_string()
        if response_contents is None:
            self.assertIn('myid1', _str)
        return _str

    def _test_list_resources_with_pagination(self, resources, cmd,
                                             base_args=None,
                                             cmd_resources=None,
                                             parent_id=None, query=""):
        if not cmd_resources:
            cmd_resources = resources

        path = getattr(self.client, cmd_resources + "_path")
        if parent_id:
            path = path % parent_id
        fake_query = "marker=myid2&limit=2"
        reses1 = {resources: [{'id': 'myid1', },
                              {'id': 'myid2', }],
                  '%s_links' % resources: [{'href': end_url(path, fake_query),
                                            'rel': 'next'}]}
        reses2 = {resources: [{'id': 'myid3', },
                              {'id': 'myid4', }]}
        resstr1 = self.client.serialize(reses1)
        resstr2 = self.client.serialize(reses2)
        cmd_parser = cmd.get_parser("list_" + cmd_resources)
        args = base_args if base_args is not None else []
        mock_request_calls = [
            mock.call(
                end_url(path, query), 'GET',
                body=None,
                headers=ContainsKeyValue({'X-Auth-Token': TOKEN})),
            mock.call(
                MyUrlComparator(end_url(path, fake_query),
                                self.client), 'GET',
                body=None,
                headers=ContainsKeyValue({'X-Auth-Token': TOKEN}))]
        mock_request_resp = [(MyResp(200), resstr1), (MyResp(200), resstr2)]

        with mock.patch.object(cmd, "get_client",
                               return_value=self.client) as mock_get_client, \
                mock.patch.object(self.client.httpclient,
                                  "request") as mock_request:
            mock_request.side_effect = mock_request_resp
            shell.run_command(cmd, cmd_parser, args)

        self.assert_mock_multiple_calls_with_same_arguments(
            mock_get_client, mock.call(), None)
        self.assertEqual(2, mock_request.call_count)
        mock_request.assert_has_calls(mock_request_calls)

    def _test_update_resource(self, resource, cmd, myid, args, extrafields,
                              cmd_resource=None, parent_id=None):
        if not cmd_resource:
            cmd_resource = resource

        body = {resource: extrafields}
        path = getattr(self.client, cmd_resource + "_path")
        if parent_id:
            path = path % (parent_id, myid)
        else:
            path = path % myid
        mock_body = MyComparator(body, self.client)

        cmd_parser = cmd.get_parser("update_" + cmd_resource)
        resp = (MyResp(204), None)

        with mock.patch.object(cmd, "get_client",
                               return_value=self.client) as mock_get_client, \
                mock.patch.object(self.client.httpclient, "request",
                                  return_value=resp) as mock_request:
            shell.run_command(cmd, cmd_parser, args)

        self.assert_mock_multiple_calls_with_same_arguments(
            mock_get_client, mock.call(), None)
        mock_request.assert_called_once_with(
            MyUrlComparator(end_url(path), self.client),
            'PUT',
            body=mock_body,
            headers=ContainsKeyValue({'X-Auth-Token': TOKEN}))
        _str = self.fake_stdout.make_string()
        self.assertIn(myid, _str)

    def _test_show_resource(self, resource, cmd, myid, args, fields=(),
                            cmd_resource=None, parent_id=None):
        if not cmd_resource:
            cmd_resource = resource

        query = "&".join(["fields=%s" % field for field in fields])
        expected_res = {resource:
                        {self.id_field: myid,
                         'name': 'myname', }, }
        resstr = self.client.serialize(expected_res)
        path = getattr(self.client, cmd_resource + "_path")
        if parent_id:
            path = path % (parent_id, myid)
        else:
            path = path % myid
        cmd_parser = cmd.get_parser("show_" + cmd_resource)
        resp = (MyResp(200), resstr)

        with mock.patch.object(cmd, "get_client",
                               return_value=self.client) as mock_get_client, \
                mock.patch.object(self.client.httpclient, "request",
                                  return_value=resp) as mock_request:
            shell.run_command(cmd, cmd_parser, args)

        self.assert_mock_multiple_calls_with_same_arguments(
            mock_get_client, mock.call(), None)
        mock_request.assert_called_once_with(
            end_url(path, query), 'GET',
            body=None,
            headers=ContainsKeyValue({'X-Auth-Token': TOKEN}))
        _str = self.fake_stdout.make_string()
        self.assertIn(myid, _str)
        self.assertIn('myname', _str)

    def _test_set_path_and_delete(self, path, parent_id, myid,
                                  mock_request_calls, mock_request_returns,
                                  delete_fail=False):
        return_val = 404 if delete_fail else 204
        if parent_id:
            path = path % (parent_id, myid)
        else:
            path = path % (myid)
        mock_request_returns.append((MyResp(return_val), None))
        mock_request_calls.append(mock.call(
            end_url(path), 'DELETE',
            body=None,
            headers=ContainsKeyValue({'X-Auth-Token': TOKEN})))

    def _test_delete_resource(self, resource, cmd, myid, args,
                              cmd_resource=None, parent_id=None,
                              extra_id=None, delete_fail=False):
        mock_request_calls = []
        mock_request_returns = []
        if not cmd_resource:
            cmd_resource = resource
        path = getattr(self.client, cmd_resource + "_path")
        self._test_set_path_and_delete(path, parent_id, myid,
                                       mock_request_calls,
                                       mock_request_returns)
        # extra_id is used to test for bulk_delete
        if extra_id:
            self._test_set_path_and_delete(path, parent_id, extra_id,
                                           mock_request_calls,
                                           mock_request_returns,
                                           delete_fail)
        cmd_parser = cmd.get_parser("delete_" + cmd_resource)

        with mock.patch.object(cmd, "get_client",
                               return_value=self.client) as mock_get_client, \
                mock.patch.object(self.client.httpclient,
                                  "request") as mock_request:
            mock_request.side_effect = mock_request_returns
            shell.run_command(cmd, cmd_parser, args)

        self.assert_mock_multiple_calls_with_same_arguments(
            mock_get_client, mock.call(), None)
        mock_request.assert_has_calls(mock_request_calls)
        _str = self.fake_stdout.make_string()
        self.assertIn(myid, _str)
        if extra_id:
            self.assertIn(extra_id, _str)

    def assert_mock_multiple_calls_with_same_arguments(
            self, mocked_method, expected_call, count):
        if count is None:
            self.assertLessEqual(1, mocked_method.call_count)
        else:
            self.assertEqual(count, mocked_method.call_count)
        mocked_method.assert_has_calls(
            [expected_call] * mocked_method.call_count)

    def check_parser_ext(self, cmd, args, verify_args, ext):
        cmd_parser = self.cmd.get_parser('check_parser')
        cmd_parser = ext.get_parser(cmd_parser)
        stderr = StringIO()
        with fixtures.MonkeyPatch('sys.stderr', stderr):
            try:
                parsed_args = cmd_parser.parse_args(args)
            except SystemExit:
                raise ParserException("Argument parse failed: %s" %
                                      stderr.getvalue())
        for av in verify_args:
            attr, value = av
            if attr:
                self.assertIn(attr, parsed_args)
                self.assertEqual(value, getattr(parsed_args, attr))
        return parsed_args


class ClientV2TestJson(CLITestV20Base):

    pass


class CLITestV20ExceptionHandler(CLITestV20Base):

    def _test_exception_handler_v20(
        self, expected_exception, status_code, expected_msg,
        error_type=None, error_msg=None, error_detail=None,
        error_content=None):
        if error_content is None:
            error_content = {'NeutronError': {'type': error_type,
                                              'message': error_msg,
                                              'detail': error_detail}}

        e = self.assertRaises(expected_exception,
                              client.exception_handler_v20,
                              status_code, error_content)
        self.assertEqual(status_code, e.status_code)

        if expected_msg is None:
            if error_detail:
                expected_msg = '\n'.join([error_msg, error_detail])
            else:
                expected_msg = error_msg
        self.assertEqual(expected_msg, e.message)

    def test_exception_handler_v20_neutron_known_error(self):
        # TODO(Sumit): This needs to be adapted for GBP
        pass

    def test_exception_handler_v20_neutron_known_error_without_detail(self):
        # TODO(Sumit): This needs to be adapted for GBP
        pass

    def test_exception_handler_v20_unknown_error_to_per_code_exception(self):
        for status_code, client_exc in list(
                exceptions.HTTP_EXCEPTION_MAP.items()):
            error_msg = 'Unknown error'
            error_detail = 'This is detail'
            self._test_exception_handler_v20(
                client_exc, status_code,
                error_msg + '\n' + error_detail,
                'UnknownError', error_msg, error_detail)

    def test_exception_handler_v20_neutron_unknown_status_code(self):
        error_msg = 'Unknown error'
        error_detail = 'This is detail'
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 501,
            error_msg + '\n' + error_detail,
            'UnknownError', error_msg, error_detail)

    def test_exception_handler_v20_bad_neutron_error(self):
        error_content = {'NeutronError': {'unknown_key': 'UNKNOWN'}}
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 500,
            expected_msg={'unknown_key': 'UNKNOWN'},
            error_content=error_content)

    def test_exception_handler_v20_error_dict_contains_message(self):
        error_content = {'message': 'This is an error message'}
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 500,
            expected_msg='This is an error message',
            error_content=error_content)

    def test_exception_handler_v20_error_dict_not_contain_message(self):
        error_content = {'error': 'This is an error message'}
        expected_msg = '%s-%s' % (500, error_content)
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 500,
            expected_msg=expected_msg,
            error_content=error_content)

    def test_exception_handler_v20_default_fallback(self):
        error_content = 'This is an error message'
        expected_msg = '%s-%s' % (500, error_content)
        self._test_exception_handler_v20(
            exceptions.NeutronClientException, 500,
            expected_msg=expected_msg,
            error_content=error_content)

    def test_exception_status(self):
        e = exceptions.BadRequest()
        self.assertEqual(e.status_code, 400)

        e = exceptions.BadRequest(status_code=499)
        self.assertEqual(e.status_code, 499)

        # SslCertificateValidationError has no explicit status_code,
        # but should have a 'safe' defined fallback.
        e = exceptions.SslCertificateValidationError()
        self.assertIsNotNone(e.status_code)

        e = exceptions.SslCertificateValidationError(status_code=599)
        self.assertEqual(e.status_code, 599)

    def test_connection_failed(self):
        self.client.httpclient.auth_token = 'token'
        excp = requests.exceptions.ConnectionError('Connection refused')

        with mock.patch.object(self.client.httpclient, "request",
                               side_effect=excp) as mock_request:
            error = self.assertRaises(exceptions.ConnectionFailed,
                                      self.client.get, '/test')

            mock_request.assert_called_once_with(
                end_url('/test'), 'GET',
                body=None,
                headers=ContainsKeyValue(
                    {'X-Auth-Token': 'token'}))
        # NB: ConnectionFailed has no explicit status_code, so this
        # tests that there is a fallback defined.
        self.assertIsNotNone(error.status_code)
