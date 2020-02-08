{{provider_name}} Common {{element_type.title()}}
{{underline(provider_name.title() + ' Common ' + element_type.title())}}

{{element_type|title}}

{% for e, resource in elements %}
   - :ref:`{{ename(e)}} <{{provider_name}}.common.{{element_type}}.{{ename(e)}}>`

{% endfor %}

{% for e, resource in elements %}
.. _{{provider_name}}.common.{{element_type}}.{{ename(e)}}:

{{ename(e)}}
{{underline(ename(e), '+')}}

{{edoc(e)}}
{{eschema(e)}}

{% endfor %}
