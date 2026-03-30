#!/usr/bin/env python3
"""
Convert existing alert rules to template format.

This script reads existing alert rule files and converts them to the template format
with multi-severity support.

Best Practices:
- Uses yaml.safe_load() for secure YAML parsing (no arbitrary code execution)
- Uses yaml.safe_dump() for secure YAML output
- Handles multi-document YAML files and invalid formats gracefully
- Preserves multi-line expressions using YAML block scalars
"""

import argparse
import copy
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from collections import defaultdict
import yaml


def load_yaml_file(file_path: Path) -> List[Dict[str, Any]]:
    """Load and parse YAML file, handling multiple documents and multiple groups blocks."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # FIRST: Check if there are multiple 'groups:' blocks (invalid YAML but common)
        # Must check this BEFORE single load because yaml.safe_load only returns last block
        groups_count = content.count('\ngroups:') + (1 if content.startswith('groups:') else 0)
        
        if groups_count > 1:
            # Handle case where file has multiple 'groups:' blocks
            sections = []
            # Split carefully - handle both cases where file starts with groups: or not
            if content.startswith('groups:'):
                parts = content.split('\ngroups:')
            else:
                parts = content.split('\ngroups:')
            
            for i, part in enumerate(parts):
                # First part keeps its content as-is (may or may not start with groups:)
                if i == 0:
                    yaml_content = part if part.strip().startswith('groups:') else None
                    if yaml_content is None:
                        continue
                else:
                    yaml_content = 'groups:' + part
                try:
                    parsed = yaml.safe_load(yaml_content)
                    if parsed and 'groups' in parsed:
                        sections.append(parsed)
                except yaml.YAMLError:
                    continue
            if sections:
                return sections
        
        # Try to load as single document
        try:
            data = yaml.safe_load(content)
            if data and 'groups' in data:
                return [data]
        except yaml.YAMLError:
            pass
        
        # Try loading multiple documents (separated by ---)
        documents = []
        try:
            for doc in yaml.safe_load_all(content):
                if doc and 'groups' in doc:
                    documents.append(doc)
            if documents:
                return documents
        except yaml.YAMLError:
            pass
        
        return []
    except Exception as e:
        print(f"Error loading {file_path}: {e}", file=sys.stderr)
        sys.exit(1)


def extract_expr_string(alert_rule: Dict[str, Any]) -> str:
    """Extract expression as string, preserving multi-line format."""
    expr = alert_rule.get('expr', '')
    if isinstance(expr, str):
        # Check if it's a multi-line expression (has actual newlines)
        if '\n' in expr:
            # Normalize: remove leading/trailing empty lines but keep structure
            lines = expr.split('\n')
            while lines and not lines[0].strip():
                lines.pop(0)
            while lines and not lines[-1].strip():
                lines.pop()
            return '\n'.join(lines)
        # Check if it has escaped newlines (literal \n characters)
        elif '\\n' in expr:
            # Convert escaped newlines to actual newlines
            unescaped = expr.replace('\\n', '\n')
            # Normalize
            lines = unescaped.split('\n')
            while lines and not lines[0].strip():
                lines.pop(0)
            while lines and not lines[-1].strip():
                lines.pop()
            return '\n'.join(lines)
        return expr.strip()
    return str(expr)


def group_alerts_by_name(alert_rules: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Group alerts by alert name."""
    grouped = defaultdict(list)
    for rule in alert_rules:
        alert_name = rule.get('alert', '')
        if alert_name:
            grouped[alert_name].append(rule)
    return grouped


def extract_common_fields(alert_rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract common fields from a group of alerts."""
    if not alert_rules:
        return {}
    
    # Use first alert as base
    base = alert_rules[0].copy()
    
    # Common annotations (from first alert)
    common = {
        'annotations': base.get('annotations', {}).copy(),
        'labels': {}
    }
    
    # Extract labels that are common across all alerts (excluding severity)
    if alert_rules:
        first_labels = alert_rules[0].get('labels', {})
        for key, value in first_labels.items():
            if key not in ['severity', 'severity_order']:
                # Check if same in all alerts
                if all(rule.get('labels', {}).get(key) == value for rule in alert_rules):
                    common['labels'][key] = value
    
    return common


def create_severity_entry(alert_rule: Dict[str, Any]) -> Dict[str, Any]:
    """Create a severity entry from an alert rule."""
    severity = alert_rule.get('labels', {}).get('severity', 'warning')
    expr = extract_expr_string(alert_rule)
    # Preserve missing 'for' as empty string if not present (don't default)
    for_duration = alert_rule.get('for', '')
    
    return {
        'level': severity,
        'expr': expr,
        'for': for_duration
    }


def convert_alerts_to_template(alert_data_list: List[Dict[str, Any]], group_name_filter: Optional[str] = None) -> Dict[str, Any]:
    """Convert alert rules to template format, handling all groups."""
    all_template_groups = []
    
    for alert_data in alert_data_list:
        groups = alert_data.get('groups', [])
        
        for group in groups:
            group_name = group.get('name', '')
            
            # Filter by group name if specified
            if group_name_filter and group_name != group_name_filter:
                continue
            
            alert_rules = group.get('rules', [])
            if not alert_rules:
                continue
            
            # Group alerts by alert name
            grouped_by_name = group_alerts_by_name(alert_rules)
            
            template_rules = []
            for alert_name, alerts in grouped_by_name.items():
                # Check for duplicate alert names with same severity
                # Group by (name, severity) to detect duplicates
                severity_groups = defaultdict(list)
                for alert in alerts:
                    severity = alert.get('labels', {}).get('severity', 'warning')
                    key = (alert_name, severity)
                    severity_groups[key].append(alert)
                
                # If we have duplicates (same name + severity), keep the original alert name.
                # vmalert/Prometheus rule format allows multiple rules with the same `alert:`
                # as long as they differ by expression/labels. The source repo relies on this,
                # so we must NOT mutate names during conversion.
                for (name, sev), dup_alerts in severity_groups.items():
                    if len(dup_alerts) > 1:
                        for idx, alert in enumerate(dup_alerts):
                            # Extract fields for this specific alert (not common)
                            alert_labels = {k: v for k, v in alert.get('labels', {}).items() 
                                          if k not in ['severity', 'severity_order']}
                            alert_annotations = alert.get('annotations', {})
                            
                            severity_entry = create_severity_entry(alert)
                            
                            template_rule = {
                                'name': name,
                                'annotations': alert_annotations,
                                'labels': alert_labels,
                                'severities': [severity_entry]
                            }
                            template_rules.append(template_rule)
                    else:
                        # Single alert - use common fields approach
                        common = extract_common_fields(dup_alerts)
                        severities = []
                        for alert in dup_alerts:
                            severity_entry = create_severity_entry(alert)
                            severities.append(severity_entry)
                        
                        # Sort severities by order: critical, warning, low, info
                        severity_order = {'critical': 0, 'warning': 1, 'low': 2, 'info': 3}
                        severities.sort(key=lambda x: severity_order.get(x['level'], 99))
                        
                        template_rule = {
                            'name': name,
                            'annotations': common.get('annotations', {}),
                            'labels': common.get('labels', {}),
                            'severities': severities
                        }
                        template_rules.append(template_rule)
            
            # Only add group if it has rules
            if template_rules:
                all_template_groups.append({
                    'name': group_name,
                    'rules': template_rules
                })
    
    return {
        'groups': all_template_groups
    }


def dump_yaml(data: Dict[str, Any], output_file: Path) -> None:
    """Dump YAML with proper formatting, preserving multi-line expressions as block scalars."""
    # Use ruamel.yaml approach: manually format block scalars after dumping
    # First pass: dump normally but track multi-line expressions
    multiline_exprs = {}  # Track expressions that need block scalar format
    expr_counter = [0]
    
    def normalize_expr(value: str) -> str:
        """Normalize expression, handling both actual and escaped newlines."""
        if '\\n' in value and len(value) > 50:
            # Convert escaped newlines to actual newlines
            value = value.replace('\\n', '\n')
        if '\n' in value:
            # Remove leading/trailing empty lines
            lines = value.split('\n')
            while lines and not lines[0].strip():
                lines.pop(0)
            while lines and not lines[-1].strip():
                lines.pop()
            return '\n'.join(lines)
        return value
    
    def mark_multiline_exprs(obj):
        """Mark multi-line expressions for special handling."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key == 'expr' and isinstance(value, str):
                    normalized = normalize_expr(value)
                    if '\n' in normalized:
                        expr_id = f"__MULTILINE_{expr_counter[0]}__"
                        expr_counter[0] += 1
                        multiline_exprs[expr_id] = normalized
                        obj[key] = expr_id
                else:
                    mark_multiline_exprs(value)
        elif isinstance(obj, list):
            for item in obj:
                mark_multiline_exprs(item)
    
    # Create a copy and mark multi-line expressions
    data_copy = copy.deepcopy(data)
    mark_multiline_exprs(data_copy)
    
    # Dump to string using safe_dump (best practice)
    yaml_str = yaml.safe_dump(
        data_copy,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=1000,
        indent=2
    )
    
    # Replace markers with properly formatted block scalars
    lines = yaml_str.split('\n')
    new_lines = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # Check if this line contains a marker
        marker_found = None
        for expr_id, expr_value in multiline_exprs.items():
            if expr_id in line:
                marker_found = (expr_id, expr_value)
                break
        
        if marker_found:
            expr_id, expr_value = marker_found
            # Calculate indentation from the current line
            indent = len(line) - len(line.lstrip())
            indent_str = ' ' * indent
            
            # Extract the key (should be "expr:")
            key_match = line.split(':')[0].strip()
            if key_match == 'expr':
                # Replace with block scalar format
                new_lines.append(f"{indent_str}expr: |-")
                # Add expression lines with proper indentation (2 spaces more)
                for expr_line in expr_value.split('\n'):
                    new_lines.append(f"{indent_str}  {expr_line}")
            else:
                new_lines.append(line)
            i += 1
        else:
            new_lines.append(line)
            i += 1
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(new_lines))


def main():
    parser = argparse.ArgumentParser(
        description='Convert existing alert rules to template format'
    )
    parser.add_argument(
        '--input',
        type=str,
        required=True,
        help='Input alert rule file'
    )
    parser.add_argument(
        '--output',
        type=str,
        required=True,
        help='Output template file'
    )
    parser.add_argument(
        '--group-name',
        type=str,
        default=None,
        help='Optional: Group name to extract (e.g., fm.rules). If not specified, converts all groups.'
    )
    
    args = parser.parse_args()
    
    input_file = Path(args.input)
    output_file = Path(args.output)
    
    if not input_file.exists():
        print(f"Error: Input file does not exist: {input_file}", file=sys.stderr)
        sys.exit(1)
    
    # Load alert rules (may return multiple documents)
    alert_data_list = load_yaml_file(input_file)
    
    if not alert_data_list:
        print(f"Error: No valid alert data found in {input_file}", file=sys.stderr)
        sys.exit(1)
    
    # Convert to template
    template_data = convert_alerts_to_template(alert_data_list, args.group_name)
    
    if not template_data.get('groups'):
        if args.group_name:
            print(f"Warning: No groups found matching '{args.group_name}'", file=sys.stderr)
        else:
            print(f"Warning: No groups found in input file", file=sys.stderr)
        sys.exit(1)
    
    # Create output directory if needed
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    # Write template
    dump_yaml(template_data, output_file)
    print(f"Converted {input_file} to template: {output_file}")


if __name__ == '__main__':
    main()

