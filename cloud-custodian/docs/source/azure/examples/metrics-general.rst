Monitor - Filter resources by metrics from Azure Monitor
========================================================

Find VMs with an average Percentage CPU greater than or equal to 75% over the last 12 hours

.. code-block:: yaml

    policies:
      - name: find-busy-vms
        description: Find VMs with avg cpu >= 75% over the last 12 hours
        resource: azure.vm
        filters:
          - type: metric
            metric: Percentage CPU
            aggregation: average
            op: ge
            threshold: 75
            timeframe: 12

Find KeyVaults with more than 1000 API hits in the last hour

.. code-block:: yaml

    policies:
      - name: keyvault-hits
        resource: azure.keyvault
        filters:
        - type: metric
          metric: ServiceApiHit
          aggregation: total
          op: gt
          threshold: 1000
          timeframe: 1

Find SQL servers with less than 10% average DTU consumption over last 24 hours

.. code-block:: yaml

    policies:
      - name: dtu-consumption
        resource: azure.sqlserver
        filters:
          - type: metric
            metric: dtu_consumption_percent
            aggregation: average
            op: lt
            threshold: 10
            timeframe: 24
            filter:  "DatabaseResourceId eq '*'"
