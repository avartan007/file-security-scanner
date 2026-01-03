import csv
import json
from datetime import datetime
from pathlib import Path

class AuditLogger:
    """Maintain immutable chain of custody and audit trails."""
    
    def __init__(self, log_file="audit_trail.csv"):
        self.log_file = log_file
        self._init_log()
    
    def _init_log(self):
        """Initialize audit log file with headers if it doesn't exist."""
        if not Path(self.log_file).exists():
            with open(self.log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Timestamp',
                    'File Hash',
                    'Filename',
                    'Action',
                    'Details',
                    'Status',
                    'Risk Level'
                ])
    
    def log_action(self, file_hash, filename, action, details="", status="OK", risk_level="UNKNOWN"):
        """Log an action to the audit trail (append-only)."""
        with open(self.log_file, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                file_hash[:16] + "...",
                filename,
                action,
                details,
                status,
                risk_level
            ])
    
    def generate_chain_of_custody(self, file_hash, output_file=None):
        """Generate chain of custody report for a specific file."""
        if output_file is None:
            output_file = f"custody_{file_hash[:8]}.json"
        
        records = []
        with open(self.log_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if file_hash[:16] in row['File Hash']:
                    records.append(row)
        
        if records:
            with open(output_file, 'w') as f:
                json.dump({
                    "file_hash": file_hash,
                    "custody_chain": records
                }, f, indent=2)
            return output_file
        
        return None
    
    def generate_summary_report(self, output_file="audit_summary.json"):
        """Generate summary statistics from audit log."""
        actions = {}
        risk_counts = {}
        
        with open(self.log_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                action = row['Action']
                risk = row['Risk Level']
                
                actions[action] = actions.get(action, 0) + 1
                risk_counts[risk] = risk_counts.get(risk, 0) + 1
        
        summary = {
            "generated": datetime.now().isoformat(),
            "total_actions": sum(actions.values()),
            "actions_by_type": actions,
            "files_by_risk": risk_counts
        }
        
        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        return output_file
