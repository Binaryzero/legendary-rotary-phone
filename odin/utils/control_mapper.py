#!/usr/bin/env python3
"""Maps ATT&CK techniques to NIST 800-53 controls using official MITRE data."""

import csv
import logging
import urllib.request
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class ControlMapper:
    """Maps ATT&CK techniques to NIST 800-53 controls using official MITRE data."""
    
    def __init__(self):
        self.mappings: Dict[str, List[Dict[str, str]]] = {}
        self.control_families: Dict[str, str] = {}
        self._load_mappings()
    
    def _load_mappings(self):
        """Load ATT&CK to NIST 800-53 mappings from official MITRE data."""
        try:
            logger.debug("Loading ATT&CK to NIST 800-53 mappings...")
            
            # Download official MITRE mappings
            url = "https://center-for-threat-informed-defense.github.io/mappings-explorer/data/nist_800_53/attack-16.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-16.1-enterprise.csv"
            
            with urllib.request.urlopen(url) as response:
                content = response.read().decode('utf-8')
                reader = csv.DictReader(content.splitlines())
                
                for row in reader:
                    # Only process actual mitigation mappings (not non_mappable)
                    if row.get('mapping_type') == 'mitigates' and row.get('capability_id'):
                        attack_id = row.get('attack_object_id', '')
                        
                        if attack_id not in self.mappings:
                            self.mappings[attack_id] = []
                        
                        control_mapping = {
                            'control_id': row.get('capability_id', ''),
                            'control_family': row.get('capability_group', ''),
                            'control_description': row.get('capability_description', ''),
                            'comments': row.get('comments', '')
                        }
                        
                        self.mappings[attack_id].append(control_mapping)
                        
                        # Track control families
                        if control_mapping['control_family']:
                            self.control_families[control_mapping['control_id']] = control_mapping['control_family']
            
            logger.debug(f"Loaded {len(self.mappings)} ATT&CK technique mappings to NIST controls")
            
        except Exception as e:
            logger.warning(f"Failed to load control mappings: {e}")
            # Fallback to empty mappings
            self.mappings = {}
            self.control_families = {}
    
    def get_controls_for_techniques(self, attack_techniques: List[str]) -> Dict[str, Any]:
        """Get NIST controls for given ATT&CK techniques."""
        if not attack_techniques:
            return {
                'applicable_controls_count': 0,
                'control_categories': '',
                'top_controls': ''
            }
        
        all_controls = []
        control_families = set()
        
        for technique in attack_techniques:
            # Handle both T1234 and T1234.001 formats
            base_technique = technique.split('.')[0] if '.' in technique else technique
            
            # Check both full technique ID and base technique
            for tech_id in [technique, base_technique]:
                if tech_id in self.mappings:
                    for control in self.mappings[tech_id]:
                        all_controls.append(control)
                        if control['control_family']:
                            control_families.add(control['control_family'])
        
        # Remove duplicates and get top controls
        unique_controls = {}
        for control in all_controls:
            control_id = control['control_id']
            if control_id not in unique_controls:
                unique_controls[control_id] = control
        
        # Sort by control ID for consistency
        sorted_controls = sorted(unique_controls.values(), key=lambda x: x['control_id'])
        
        # Format top controls (limit to top 5)
        top_controls = []
        for control in sorted_controls[:5]:
            control_desc = f"{control['control_id']}: {control['control_description']}"
            top_controls.append(control_desc)
        
        return {
            'applicable_controls_count': len(unique_controls),
            'control_categories': '; '.join(sorted(control_families)) if control_families else '',
            'top_controls': '; '.join(top_controls) if top_controls else ''
        }