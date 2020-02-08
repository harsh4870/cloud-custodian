.. _{{resource_name}}:

{{resource_name}}
{{underline(resource_name)}}

{% if resource.__doc__ %}{{edoc(resource)}}{% endif %}

Filters
-------

{% for f in filters %}{% if f.schema_alias %}
  - :ref:`{{ename(f)}} <{{provider_name}}.common.filters.{{ename(f)}}>`
  {% else %}
  - :ref:`{{ename(f)}} <{{resource_name}}.filters.{{ename(f)}}>`
{% endif %}{% endfor %}

{% for f in filters %}{% if not f.schema_alias %}
.. _{{resource_name}}.filters.{{ename(f)}}:

{{ename(f)}}
{{underline(ename(f), '+')}}
{{edoc(f)}}
{{eschema(f)}}
{% endif %}{% endfor %}


Actions
-------

{% for a in actions %}{% if a.schema_alias %}
  - :ref:`{{ename(a)}} <{{provider_name}}.common.actions.{{ename(a)}}>`
  {% else %}
  - :ref:`{{ename(a)}} <{{resource_name}}.actions.{{ename(a)}}>`
{% endif %}{% endfor %}


{% for a in actions %}{% if not a.schema_alias %}
.. _{{resource_name}}.actions.{{ename(a)}}:

{{ename(a)}}
{{underline(ename(a), '+')}}
{{edoc(a)}}
{{eschema(a)}}
{% endif %}{% endfor %}
