#!/usr/bin/env python3
"""
Generate vmalert-compatible alert rules from template files.

Best Practices:
- Uses yaml.safe_load() for secure YAML parsing
- Uses yaml.safe_dump() for secure YAML output
- Preserves multi-line expressions as YAML block scalars

This script reads template files in the format:
  groups:
    - name: <group-name>
      rules:
        - name: <alert-name>
          annotations: {...}
          labels: {...}
          severities:
            - level: critical
              expr: |
                <multi-line expression>
              for: 2m
            ...

And generates standard Prometheus alert rules:
  groups:
    - name: <group-name>
      rules:
        - alert: <alert-name>
          expr: |
            <multi-line expression>
          for: 2m
          labels:
            severity: critical
            severity_order: "1"
            ...
          annotations: {...}
"""

import argparse
import os
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Any, Set
import yaml


# Output subdirs that are NOT generated from templates - never touch these
OUTPUT_SUBDIRS_EXCLUDE = frozenset({"recording-rules"})


# Severity order mapping
SEVERITY_ORDER = {
    'critical': '1',
    'warning': '2',
    'low': '3',
    'info': '4'
}


def load_yaml_file(file_path: Path) -> Dict[str, Any]:
    """Load and parse YAML file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    except Exception as e:
        raise ValueError(f"Failed to parse YAML: {e}")


def preserve_block_scalar(expr: str) -> str:
    """Preserve multi-line expressions as block scalars."""
    # If expression contains newlines, it should be a block scalar
    if '\n' in expr:
        # Remove leading/trailing whitespace but preserve internal structure
        lines = expr.split('\n')
        # Remove empty leading/trailing lines
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
        return '\n'.join(lines)
    return expr.strip()


def is_enabled(value: Any) -> bool:
    """
    Interpret `enabled` flag from YAML.

    Supported values:
    - true/false (bool)
    - "true"/"false", "yes"/"no", "1"/"0" (string)
    - missing / None -> enabled
    """
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("false", "no", "0", "off", "disabled"):
            return False
        if v in ("true", "yes", "1", "on", "enabled"):
            return True
    # Default to enabled for unknown values to avoid accidentally disabling alerts
    return True


def generate_alert_rule(template_rule: Dict[str, Any], severity: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a single alert rule from template rule and severity definition."""
    alert_name = template_rule.get('name', '')
    
    if not isinstance(severity, dict):
        raise ValueError(
            f"Alert '{alert_name}': expected severity dict, got {type(severity).__name__}. "
            "Check for mis-indented rules under 'severities'."
        )
    if 'expr' not in severity:
        raise ValueError(
            f"Alert '{alert_name}': severity entry missing 'expr'. "
            "Each severity must have 'expr' and 'level'. "
            "Check for mis-indented rules (e.g. sibling rule nested under severities)."
        )
    if 'level' not in severity:
        raise ValueError(
            f"Alert '{alert_name}': severity entry missing 'level'. "
            "Each severity must have 'expr' and 'level'."
        )
    
    # Build the alert rule
    alert_rule = {
        'alert': alert_name,
        'expr': preserve_block_scalar(severity['expr']),
        'labels': {},
        'annotations': {}
    }
    
    # Only add 'for' if it's not empty
    if severity.get('for'):
        alert_rule['for'] = severity['for']
    
    # Copy labels from template, add severity labels
    if 'labels' in template_rule:
        alert_rule['labels'].update(template_rule['labels'])
    
    # Add severity-specific labels
    severity_level = severity['level']
    alert_rule['labels']['severity'] = severity_level
    alert_rule['labels']['severity_order'] = SEVERITY_ORDER.get(severity_level, '0')
    
    # Copy annotations from template
    if 'annotations' in template_rule:
        alert_rule['annotations'].update(template_rule['annotations'])
    
    return alert_rule


def process_template_group(template_group: Dict[str, Any]) -> Dict[str, Any]:
    """Process a template group and generate alert rules."""
    group_name = template_group.get('name', '')
    template_rules = template_group.get('rules', [])
    
    generated_rules = []
    
    for template_rule in template_rules:
        # Allow per-alert disable without deleting files.
        # Default is enabled when the flag is missing.
        if not is_enabled(template_rule.get('enabled')):
            continue

        # Get severities from template
        severities = template_rule.get('severities', [])
        
        if not severities:
            print(f"Warning: Alert '{template_rule.get('name')}' has no severities defined", file=sys.stderr)
            continue
        
        # Generate one alert rule per severity
        for severity in severities:
            alert_rule = generate_alert_rule(template_rule, severity)
            generated_rules.append(alert_rule)
    
    return {
        'name': group_name,
        'rules': generated_rules
    }


def generate_alerts_from_template(template_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generate alert rules from template data."""
    template_groups = template_data.get('groups', [])
    
    generated_groups = []
    for template_group in template_groups:
        generated_group = process_template_group(template_group)
        if generated_group['rules']:  # Only add groups with rules
            generated_groups.append(generated_group)
    
    return {'groups': generated_groups}


def dump_yaml(data: Dict[str, Any], output_file: Path) -> None:
    """Dump YAML with proper formatting to preserve multi-line expressions."""
    class BlockScalarStr(str):
        """Custom string class to preserve block scalar style."""
        pass
    
    def block_scalar_str_representer(dumper, data):
        """Representer for block scalar strings."""
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    
    # Add representer to SafeDumper for security (best practice)
    yaml.add_representer(BlockScalarStr, block_scalar_str_representer, Dumper=yaml.SafeDumper)
    
    # Convert multi-line expressions to BlockScalarStr
    def convert_block_scalars(obj):
        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                if key == 'expr' and isinstance(value, str) and '\n' in value:
                    result[key] = BlockScalarStr(value)
                else:
                    result[key] = convert_block_scalars(value)
            return result
        elif isinstance(obj, list):
            return [convert_block_scalars(item) for item in obj]
        return obj
    
    converted_data = convert_block_scalars(data)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.safe_dump(
            converted_data,
            f,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
            width=1000,  # Prevent line wrapping
            indent=2
        )


def process_template_file(template_file: Path, template_dir: Path, output_dir: Path, format_type: str) -> None:
    """Process a single template file and generate alert rules."""
    print(f"Processing template: {template_file}")
    
    # Load template
    template_data = load_yaml_file(template_file)
    
    try:
        generated_data = generate_alerts_from_template(template_data)
    except (KeyError, TypeError) as e:
        raise ValueError(
            f"Invalid template structure in {template_file}: {e}\n"
            "Each entry under 'severities' must have 'expr' and 'level' keys. "
            "Check for mis-indented rules (e.g. a sibling rule nested under severities)."
        ) from e

    # Compute output path early so we can delete stale outputs when everything is disabled
    try:
        rel_path = template_file.relative_to(template_dir)
    except ValueError:
        rel_path = Path(template_file.name)
    if format_type == 'old':
        output_path = (output_dir / rel_path).with_suffix('')
    else:
        output_path = output_dir / rel_path
    
    if not generated_data['groups']:
        # If all alerts in the template are disabled (or invalid), remove any stale output file
        # so vmalert doesn't keep loading old rules.
        if output_path.exists():
            print(f"Warning: No groups generated from {template_file}. Deleting stale generated file: {output_path}", file=sys.stderr)
            output_path.unlink()
        else:
            print(f"Warning: No groups generated from {template_file}", file=sys.stderr)
        return
    
    # Create output directory if needed
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write generated alerts
    dump_yaml(generated_data, output_path)
    print(f"Generated: {output_path}")


def find_template_files(template_dir: Path) -> List[Path]:
    """Find all template YAML files."""
    template_files = []
    for root, dirs, files in os.walk(template_dir):
        root_path = Path(root)

        for file in files:
            if file.endswith('.yaml') or file.endswith('.yml'):
                template_files.append(Path(root) / file)

    return sorted(template_files)


def _is_generated_rule_file(output_file: Path, format_type: str) -> bool:
    """
    Check if this file could be a generated rule output (vs e.g. .gitkeep).
    Covers both formats so we catch orphans when switching formats or legacy files.
    """
    if not output_file.is_file():
        return False
    if output_file.name in (".gitkeep", ".gitignore"):
        return False
    # Fleet format outputs .yaml/.yml; old format outputs extensionless
    if output_file.suffix in (".yaml", ".yml"):
        return True
    if format_type == "old" and output_file.suffix == "":
        return True
    return False


def remove_orphaned_outputs(
    template_dir: Path,
    output_dir: Path,
    format_type: str,
    expected_output_paths: Set[Path],
) -> int:
    """
    Remove generated files that no longer have a corresponding template.
    Handles: (1) orphaned files within subdirs, (2) entire subdirs whose template
    subdir was deleted (e.g. alert-templates/infra-rules removed).
    Does NOT touch recording-rules (which are not generated from templates).
    Returns the number of orphaned files/dirs removed.
    """
    removed = 0
    template_subdir_names = {
        d.name for d in template_dir.iterdir() if d.is_dir()
    }

    # 1. Within each template subdir: remove orphaned files
    for template_subdir in sorted(template_dir.iterdir()):
        if not template_subdir.is_dir():
            continue
        output_subdir = output_dir / template_subdir.name
        if not output_subdir.exists():
            continue
        for output_file in output_subdir.rglob("*"):
            if not _is_generated_rule_file(output_file, format_type):
                continue
            output_file_resolved = output_file.resolve()
            if output_file_resolved not in expected_output_paths:
                print(
                    f"Removing orphaned generated file (no matching template): {output_file_resolved}",
                    file=sys.stderr,
                )
                output_file.unlink()
                removed += 1

    # 2. Remove entire output subdirs whose template subdir was deleted
    if not output_dir.exists():
        return removed
    for output_subdir in sorted(output_dir.iterdir()):
        if not output_subdir.is_dir():
            continue
        if output_subdir.name in OUTPUT_SUBDIRS_EXCLUDE:
            continue
        if output_subdir.name in template_subdir_names:
            continue
        # Template subdir was deleted - remove entire output subdir
        for f in output_subdir.rglob("*"):
            if f.is_file():
                print(
                    f"Removing orphaned generated file (template subdir deleted): {f.resolve()}",
                    file=sys.stderr,
                )
                f.unlink()
                removed += 1
        shutil.rmtree(output_subdir, ignore_errors=True)
        print(
            f"Removed orphaned output subdir (no matching template subdir): {output_subdir}",
            file=sys.stderr,
        )

    return removed


def main():
    parser = argparse.ArgumentParser(
        description='Generate vmalert alert rules from templates'
    )
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Input directory containing template files'
    )
    parser.add_argument(
        '--output',
        type=str,
        required=True,
        help='Output directory for generated alert rules'
    )
    parser.add_argument(
        '--format',
        type=str,
        choices=['old', 'fleet'],
        default='old',
        help='Output format: old (no extension) or fleet (.yaml extension)'
    )
    
    args = parser.parse_args()
    
    template_dir = Path(args.input)
    output_dir = Path(args.output)
    
    if not template_dir.exists():
        print(f"Error: Template directory does not exist: {template_dir}", file=sys.stderr)
        sys.exit(1)
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Find and process all template files
    template_files = find_template_files(template_dir)
    
    if not template_files:
        print(f"Warning: No template files found in {template_dir}", file=sys.stderr)
        return
    
    print(f"Found {len(template_files)} template file(s)")
    
    # Build set of expected output paths (for orphan cleanup when templates are deleted)
    expected_output_paths: Set[Path] = set()
    
    processed = 0
    failed = 0
    failed_files = []
    for template_file in template_files:
        output_path = None
        try:
            # Compute output path for expected set
            try:
                rel_path = template_file.relative_to(template_dir)
            except ValueError:
                rel_path = Path(template_file.name)
            if args.format == 'old':
                output_path = (output_dir / rel_path).with_suffix('')
            else:  # fleet format
                output_path = output_dir / rel_path
            expected_output_paths.add(output_path.resolve())
            
            process_template_file(template_file, template_dir, output_dir, args.format)
            processed += 1
        except Exception as e:
            failed_files.append((template_file, str(e)))
            print(f"ERROR: Failed to process {template_file}", file=sys.stderr)
            print(f"  Reason: {e}", file=sys.stderr)
            failed += 1
            if output_path is not None:
                expected_output_paths.discard(output_path.resolve())
                # Delete corresponding generated file if it exists, so git sees a change
                if output_path.exists():
                    print(f"  Deleting stale generated file: {output_path}", file=sys.stderr)
                    output_path.unlink()
            continue
    
    # Remove orphaned outputs: generated files whose templates were deleted
    removed = remove_orphaned_outputs(
        template_dir, output_dir, args.format, expected_output_paths
    )
    if removed > 0:
        print(f"Removed {removed} orphaned generated file(s)", file=sys.stderr)
    
    if processed == 0 and failed > 0:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"ERROR: All template files failed to process", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        for template_file, error in failed_files:
            print(f"  - {template_file}: {error}", file=sys.stderr)
        sys.exit(1)
    
    if failed > 0:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"ERROR: {failed} template file(s) failed to process. Build will fail.", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        print(f"Failed files:", file=sys.stderr)
        for template_file, error in failed_files:
            print(f"  - {template_file}", file=sys.stderr)
            print(f"    Error: {error}", file=sys.stderr)
        print(f"\nSuccessfully processed {processed} template file(s)", file=sys.stderr)
        sys.exit(1)
    
    print(f"\nSuccessfully generated {processed} alert rule file(s)")


if __name__ == '__main__':
    main()

