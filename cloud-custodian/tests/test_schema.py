# Copyright 2016-2017 Capital One Services, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function, unicode_literals

import mock
import sys
from jsonschema.exceptions import best_match

from c7n.exceptions import PolicyValidationError
from c7n.filters import ValueFilter
from c7n.resources import load_resources
from c7n.schema import (
    StructureParser, ElementSchema, resource_vocabulary,
    JsonSchemaValidator, validate, generate,
    specific_error, policy_error_scope)
from .common import BaseTest


class StructureParserTest(BaseTest):

    def test_extra_keys(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'accounts': []})
        self.assertTrue(str(ecm.exception).startswith('Policy files top level keys'))

    def test_bad_top_level_datastruct(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate([])
        self.assertTrue(str(ecm.exception).startswith(
            'Policy file top level data structure'))

    def test_policies_missing(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({})
        self.assertTrue(str(ecm.exception).startswith(
            "`policies` list missing"))

    def test_policies_not_list(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'policies': {}})
        self.assertTrue(str(ecm.exception).startswith(
            "`policies` key should be an array/list"))

    def test_policy_missing_required(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'policies': [{'resource': 'aws.ec2'}]})
        self.assertTrue(str(ecm.exception).startswith(
            "policy missing required keys"))

    def test_policy_extra_key(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'policies': [{
                'name': 'foo', 'extra': 1, 'resource': 'aws.ec2'}]})
        self.assertEqual(str(ecm.exception),
            "policy:foo has unknown keys: extra")

    def test_invalid_action(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'policies': [{
                'name': 'foo', 'resource': 'ec2', 'actions': {}}]})
        self.assertTrue(str(ecm.exception).startswith(
            'policy:foo must use a list for actions found:dict'))

        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'policies': [{
                'name': 'foo', 'resource': 'ec2', 'actions': [[]]}]})
        self.assertTrue(str(ecm.exception).startswith(
            'policy:foo action must be a mapping/dict found:list'))

    def test_invalid_filter(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'policies': [{
                'name': 'foo', 'resource': 'ec2', 'filters': {}}]})
        self.assertTrue(str(ecm.exception).startswith(
            'policy:foo must use a list for filters found:dict'))
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'policies': [{
                'name': 'foo', 'resource': 'ec2', 'filters': [[]]}]})
        self.assertTrue(str(ecm.exception).startswith(
            'policy:foo filter must be a mapping/dict found:list'))

    def test_policy_not_mapping(self):
        p = StructureParser()
        with self.assertRaises(PolicyValidationError) as ecm:
            p.validate({'policies': [[]]})
        self.assertTrue(str(ecm.exception).startswith(
            'policy must be a dictionary/mapping found:list'))

    def test_get_resource_types(self):
        p = StructureParser()
        self.assertEqual(
            p.get_resource_types({'policies': [
                {'resource': 'ec2'}, {'resource': 'gcp.instance'}]}),
            set(('aws.ec2', 'gcp.instance')))


class SchemaTest(BaseTest):

    validator = None

    def findError(self, data, validator):
        e = best_match(validator.iter_errors(data))
        ex = specific_error(list(validator.iter_errors(data))[0])
        return e, ex

    def setUp(self):
        if not self.validator:
            self.validator = JsonSchemaValidator(generate())

    def get_validator(self, data):
        # return a jsonschema validator for the policy data
        # use the policy loader to load the resource types
        self.policy_loader.load_data(
            data, file_uri='memory://', validate=False)
        rtypes = StructureParser().get_resource_types(data)
        return self.policy_loader.validator.gen_schema(tuple(rtypes))

    def test_empty_skeleton(self):
        self.assertEqual(
            self.policy_loader.validator.validate(
                {"policies": []}),
            [])

    def test_duplicate_policies(self):
        data = {
            "policies": [
                {"name": "monday-morning", "resource": "ec2"},
                {"name": "monday-morning", "resource": "ec2"}]}
        # use the policy loader to load the resource types
        self.policy_loader.load_data(
            data, file_uri='memory://', validate=False)
        result = self.policy_loader.validator.validate(data)
        self.assertEqual(len(result), 2)
        self.assertTrue(isinstance(result[0], ValueError))
        self.assertTrue("monday-morning" in str(result[0]))

    def test_py3_policy_error(self):
        data = {
            'policies': [{
                'name': 'policy-ec2',
                'resource': 'ec2',
                'actions': [
                    {'type': 'terminate',
                     'force': 'asdf'}]}]}
        self.policy_loader.load_data(
            data, file_uri='memory://', validate=False)
        result = self.policy_loader.validator.validate(data)
        self.assertEqual(len(result), 2)
        err, policy = result
        self.assertTrue("'asdf' is not of type 'boolean'" in str(err).replace("u'", "'"))
        self.assertEqual(policy, 'policy-ec2')

    def test_semantic_error_common_filter_provider_prefixed(self):
        data = {
            'policies': [{
                'name': 'test',
                'resource': 's3',
                'filters': [{
                    'type': 'metrics',
                    'name': 'BucketSizeBytes',
                    'dimensions': [{
                        'StorageType': 'StandardStorage'}],
                    'days': 7,
                    'value': 100,
                    'op': 'gte'}]}]}
        # load s3 resource
        validator = self.get_validator(data)
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 1)
        error = specific_error(errors[0])
        # the repr unicode situation on py2.7 makes this harder to do
        # an exact match
        if sys.version_info.major == 2:
            return self.assertIn('StorageType', str(error))
        self.assertIn(
            "[{'StorageType': 'StandardStorage'}] is not of type 'object'",
            str(error))

    def test_semantic_mode_error(self):
        data = {
            'policies': [{
                'name': 'test',
                'resource': 'ec2',
                'mode': {
                    'type': 'periodic',
                    'scheduled': 'oops'}}]}
        validator = self.get_validator(data)
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 1)
        error = specific_error(errors[0])
        self.assertTrue(
            len(errors[0].absolute_schema_path) < len(error.absolute_schema_path)
        )
        self.assertTrue("'scheduled' was unexpected" in str(error))
        self.assertTrue(len(str(error)) < 2000)

    def test_semantic_error_policy_scope(self):
        data = {
            'policies': [
                {'actions': [{'key': 'TagPolicyCompliance',
                              'type': 'tag',
                              'value': 'This resource should have tags following policy'}],
                 'description': 'Identify resources which lack our accounting tags',
                 'filters': [{'tag:Environment': 'absent'},
                             {'tag:Service': 'absent'},
                             {'or': [{'tag:Owner': 'absent'},
                                     {'tag:ResponsibleParty': 'absent'},
                                     {'tag:Contact': 'absent'},
                                     {'tag:Creator': 'absent'}]}],
                 'name': 'tagging-compliance-waf',
                 'resource': 'aws.waf'}]}
        load_resources(('aws.waf',))
        validator = self.policy_loader.validator.gen_schema(('aws.waf',))
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 1)
        error = policy_error_scope(specific_error(errors[0]), data)
        self.assertTrue("policy:tagging-compliance-waf" in error.message)

    def test_semantic_error(self):
        data = {
            "policies": [
                {
                    "name": "test",
                    "resource": "ec2",
                    "filters": {"type": "ebs", "skipped_devices": []},
                }
            ]
        }
        load_resources(('aws.ec2',))
        validator = self.policy_loader.validator.gen_schema(('aws.ec2',))
        # probably should just ditch this test
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 1)
        error = specific_error(errors[0])
        self.assertTrue(
            len(errors[0].absolute_schema_path) < len(error.absolute_schema_path)
        )

        self.assertTrue("'skipped_devices': []" in error.message)
        self.assertTrue(
            "u'type': u'ebs'" in error.message or "'type': 'ebs'" in error.message
        )

    @mock.patch("c7n.schema.specific_error")
    def test_handle_specific_error_fail(self, mock_specific_error):
        from jsonschema.exceptions import ValidationError
        data = {
            "policies": [
                {
                    "name": "test",
                    "resource": "aws.ec2",
                    "filters": {"type": "ebs", "invalid": []},
                }
            ]
        }
        mock_specific_error.side_effect = ValueError(
            "The specific error crapped out hard"
        )

        resp = validate(data)
        # if it is 2, then we know we got the exception from specific_error
        self.assertEqual(len(resp), 2)
        self.assertIsInstance(resp[0], ValidationError)
        self.assertIsInstance(resp[1], ValidationError)

    def test_semantic_error_with_nested_resource_key(self):
        data = {
            'policies': [{
                'name': 'team-tag-ebs-snapshot-audit',
                'resource': 'ebs-snapshot',
                'actions': [
                    {'type': 'copy-related-tag',
                     'resource': 'ebs',
                     'skip_missing': True,
                     'key': 'VolumeId',
                     'tags': 'Team'}]}]}
        validator = self.get_validator(data)
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 1)
        error = specific_error(errors[0])
        self.assertTrue('Team' in error.message)

    def test_vars_and_tags(self):
        data = {
            "vars": {"alpha": 1, "beta": 2},
            "policies": [{"name": "test", "resource": "ec2", "tags": ["controls"]}],
        }
        validator = self.get_validator(data)
        self.assertEqual(list(validator.iter_errors(data)), [])

    def test_semantic_error_on_value_derived(self):
        data = {
            "policies": [
                {
                    "name": "test",
                    "resource": "ec2",
                    "filters": [{"type": "ebs", "skipped_devices": []}],
                }
            ]
        }
        validator = self.get_validator(data)
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 1)
        error = specific_error(errors[0])
        self.assertTrue(
            len(errors[0].absolute_schema_path) < len(error.absolute_schema_path)
        )
        self.assertTrue("Additional properties are not allowed " in error.message)
        self.assertTrue("'skipped_devices' was unexpected" in error.message)

    def test_invalid_resource_type(self):
        data = {
            "policies": [{"name": "instance-policy",
                          "resource": "ec3", "filters": []}]
        }
        self.assertRaises(PolicyValidationError, self.get_validator, data)

    def xtest_value_filter_short_form_invalid(self):
        # this tests helps smoke out overly permissive schemas
        rtypes = ('aws.elb',)
        load_resources(rtypes)
        for rtype in rtypes:
            data = {
                "policies": [
                    {
                        "name": "instance-policy",
                        "resource": rtype,
                        "filters": [{"tag:Role": "webserver"}],
                    }
                ]
            }

            validator = self.policy_loader.validator.gen_schema((rtype,))
            # Disable standard value short form
            validator.schema["definitions"]["filters"][
                "valuekv"] = {"type": "number"}
            errors = list(validator.iter_errors(data))
            self.assertEqual(len(errors), 1)

    def test_nested_bool_operators(self):
        data = {
            "policies": [
                {
                    "name": "test",
                    "resource": "ec2",
                    "filters": [
                        {
                            "or": [
                                {"tag:Role": "webserver"},
                                {"type": "value", "key": "x", "value": []},
                                {"and": [{"tag:Name": "cattle"}, {"tag:Env": "prod"}]},
                            ]
                        }
                    ],
                }
            ]
        }
        errors = list(self.validator.iter_errors(data))
        self.assertEqual(errors, [])

    def test_bool_operator_child_validation(self):
        data = {'policies': [
            {'name': 'test', 'resource': 'ec2', 'filters': [
                {'or': [{'type': 'imagex', 'key': 'tag:Foo', 'value': 'a'}]}]}]}
        errors = list(self.validator.iter_errors(data))
        self.assertTrue(errors)

    def test_value_filter_short_form(self):
        data = {
            "policies": [
                {
                    "name": "instance-policy",
                    "resource": "elb",
                    "filters": [{"tag:Role": "webserver"}],
                }
            ]
        }
        validator = self.get_validator(data)
        errors = list(validator.iter_errors(data))
        self.assertEqual(errors, [])

    def test_event_inherited_value_filter(self):
        data = {
            "policies": [
                {
                    "name": "test",
                    "resource": "ec2",
                    "filters": [
                        {
                            "type": "event",
                            "key": "detail.requestParameters",
                            "value": "absent",
                        }
                    ],
                }
            ]
        }
        errors = list(self.validator.iter_errors(data))
        self.assertEqual(errors, [])

    def test_ebs_inherited_value_filter(self):
        data = {
            "policies": [
                {
                    "name": "test",
                    "resource": "ec2",
                    "filters": [
                        {
                            "type": "ebs",
                            "key": "Encrypted",
                            "value": False,
                            "skip-devices": ["/dev/sda1", "/dev/xvda"],
                        }
                    ],
                }
            ]
        }
        errors = list(self.validator.iter_errors(data))
        self.assertEqual(errors, [])

    def test_offhours_stop(self):
        data = {
            "policies": [
                {
                    "name": "ec2-offhours-stop",
                    "resource": "ec2",
                    "filters": [
                        {"tag:aws:autoscaling:groupName": "absent"},
                        {
                            "type": "offhour",
                            "tag": "c7n_downtime",
                            "default_tz": "et",
                            "offhour": 19,
                        },
                    ],
                }
            ]
        }
        validator = self.get_validator(data)
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 0)

    def test_instance_age(self):
        data = {
            "policies": [
                {
                    "name": "ancient-instances",
                    "resource": "ec2",
                    "query": [{"instance-state-name": "running"}],
                    "filters": [{"days": 60, "type": "instance-age"}],
                }
            ]
        }
        errors = list(self.get_validator(data).iter_errors(data))
        self.assertEqual(len(errors), 0)

    def test_mark_for_op(self):
        data = {
            "policies": [
                {
                    "name": "ebs-mark-delete",
                    "resource": "ebs",
                    "filters": [],
                    "actions": [{"type": "mark-for-op", "op": "delete", "days": 30}],
                }
            ]
        }
        validator = self.get_validator(data)
        errors = list(validator.iter_errors(data))
        self.assertEqual(len(errors), 0)

    def test_runtime(self):
        data = {
            "policies": [
                {
                    "name": "test",
                    "resource": "s3",
                    "mode": {
                        "execution-options": {"metrics_enabled": False},
                        "type": "periodic",
                        "schedule": "xyz",
                        "runtime": None
                    },
                }
            ]
        }
        self.policy_loader.load_data(
            data, file_uri='memory://', validate=False)

        def errors_with(runtime):
            data['policies'][0]['mode']['runtime'] = runtime
            return self.policy_loader.validator.validate(data)

        self.assertEqual(len(errors_with("python2.7")), 0)
        self.assertEqual(len(errors_with("python3.6")), 0)
        self.assertEqual(len(errors_with("python4.5")), 2)

    def test_element_resolve(self):
        vocab = resource_vocabulary()
        self.assertEqual(ElementSchema.resolve(vocab, 'mode.periodic').type, 'periodic')
        self.assertEqual(ElementSchema.resolve(vocab, 'aws.ec2').type, 'ec2')
        self.assertEqual(ElementSchema.resolve(vocab, 'aws.ec2.actions.stop').type, 'stop')
        self.assertRaises(ValueError, ElementSchema.resolve, vocab, 'aws.ec2.actions.foo')

    def test_element_doc(self):

        class A(object):
            pass

        class B(object):
            """Hello World

            xyz
            """

        class C(B):
            pass

        class D(ValueFilter):
            pass

        class E(ValueFilter):
            """Something"""

        class F(D):
            pass

        class G(E):
            pass

        self.assertEqual(ElementSchema.doc(G), "Something")
        self.assertEqual(ElementSchema.doc(D), "")
        self.assertEqual(ElementSchema.doc(F), "")
        self.assertEqual(
            ElementSchema.doc(B), "Hello World\n\nxyz")
