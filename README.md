# Alert Template Generator

Generate vmalert/Prometheus alert rules from a custom template format that supports multiple severity levels per alert.

**Blog post:** [Deploying Alert Rules at Scale with Fleet and Jenkins](https://dvops.dev/blog/alert-rules-fleet-jenkins)

## The Problem

Standard Prometheus alert rules require one rule per severity level. Managing 500+ rules across multiple severities means maintaining duplicate rules that drift over time.

## The Solution

Write one template with a `severities` block. The generator produces standard vmalert/Prometheus rules with proper `severity` and `severity_order` labels for AlertManager inhibition.

## Template Format

```yaml
groups:
  - name: kubernetes.rules
    rules:
      - name: CPU Close to Limits
        annotations:
          summary: "Pod CPU usage approaching resource limits"
        labels:
          team: infrastructure
        severities:
          - level: critical
            expr: |
              (sum by (namespace,pod,container,cluster)(
                rate(container_cpu_usage_seconds_total[5m])
              ) / sum by(namespace,pod,container,cluster)(
                kube_pod_container_resource_limits{resource="cpu"}
              )) * 100 > 95
            for: 5m
          - level: warning
            expr: |
              ...same query... > 90
            for: 5m
```

Each severity can have a completely different expression - not just different thresholds.

## Usage

### Generate rules from templates

```bash
python3 generate_from_template.py \
  --input ./templates \
  --output ./rules \
  --format fleet
```

### Convert existing rules to templates

```bash
python3 convert_to_template.py \
  --input ./existing-rules \
  --output ./templates
```

## Features

- Multiple severity levels per alert (critical, warning, low, info)
- Automatic `severity` and `severity_order` labels for AlertManager inhibition
- Per-alert `enabled: false` flag to disable without deleting
- Preserves multi-line PromQL as YAML block scalars
- Validates severity entries have required `expr` and `level` fields
- Removes orphaned generated files when templates are deleted
- Migration tool to convert existing rules to template format

## AlertManager Inhibition

The generated rules share the same `alert` name across severities. Add inhibition rules to suppress lower severities:

```yaml
inhibit_rules:
  - source_matchers:
      - severity = critical
    target_matchers:
      - severity =~ warning|info|low
    equal:
      - alertname
  - source_matchers:
      - severity = warning
    target_matchers:
      - severity =~ info|low
    equal:
      - alertname
```

## CI Integration

Use vmalert dry-run to validate generated rules before deployment:

```bash
docker run --rm \
  -v $(pwd)/rules:/rules \
  victoriametrics/vmalert:latest \
  -rule="/rules/**/*.yaml" \
  -dryRun
```

## Requirements

- Python 3.6+
- PyYAML (`pip install PyYAML`)
