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

import importlib

import jmespath

from .core import ValueFilter, OPERATORS


class RelatedResourceFilter(ValueFilter):

    schema_alias = False

    RelatedResource = None
    RelatedIdsExpression = None
    AnnotationKey = None
    FetchThreshold = 10

    def get_permissions(self):
        return self.get_resource_manager().get_permissions()

    def validate(self):
        name = self.__class__.__name__
        if self.RelatedIdsExpression is None:
            raise ValueError(
                "%s Filter requires resource expression" % name)
        # if self.AnnotationKey is None:
        #    raise ValueError(
        #        "%s Filter requires annotation key" % name)

        if self.RelatedResource is None:
            raise ValueError(
                "%s Filter requires resource manager spec" % name)
        return super(RelatedResourceFilter, self).validate()

    def get_related_ids(self, resources):
        return set(jmespath.search(
            "[].%s" % self.RelatedIdsExpression, resources))

    def get_related(self, resources):
        resource_manager = self.get_resource_manager()
        related_ids = self.get_related_ids(resources)
        model = resource_manager.get_model()
        if len(related_ids) < self.FetchThreshold:
            related = resource_manager.get_resources(list(related_ids))
        else:
            related = resource_manager.resources()
        return {r[model.id]: r for r in related
                if r[model.id] in related_ids}

    def get_resource_manager(self):
        mod_path, class_name = self.RelatedResource.rsplit('.', 1)
        module = importlib.import_module(mod_path)
        manager_class = getattr(module, class_name)
        return manager_class(self.manager.ctx, {})

    def process_resource(self, resource, related):
        related_ids = self.get_related_ids([resource])
        model = self.manager.get_model()
        op = self.data.get('operator', 'or')
        found = []

        if self.data.get('match-resource') is True:
            self.data['value'] = self.get_resource_value(
                self.data['key'], resource)

        if self.data.get('value_type') == 'resource_count':
            count_matches = OPERATORS[self.data.get('op')](len(related_ids), self.data.get('value'))
            if count_matches:
                self._add_annotations(related_ids, resource)
            return count_matches

        for rid in related_ids:
            robj = related.get(rid, None)
            if robj is None:
                self.log.warning(
                    "Resource %s:%s references non existant %s: %s",
                    self.manager.type,
                    resource[model.id],
                    self.RelatedResource.rsplit('.', 1)[-1],
                    rid)
                continue
            if self.match(robj):
                found.append(rid)

        if found:
            self._add_annotations(found, resource)

        if op == 'or' and found:
            return True
        elif op == 'and' and len(found) == len(related_ids):
            return True
        return False

    def _add_annotations(self, related_ids, resource):
        if self.AnnotationKey is not None:
            akey = 'c7n:%s' % self.AnnotationKey
            resource[akey] = list(set(related_ids).union(resource.get(akey, [])))

    def process(self, resources, event=None):
        related = self.get_related(resources)
        return [r for r in resources if self.process_resource(r, related)]
