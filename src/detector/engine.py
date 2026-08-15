from dataclasses import dataclass

from detector.indicators import TelemetryItem, Finding, analyze_item

@dataclass
class DetectionResult:
    score: int
    severity: str
    findings: list[Finding]
    items_analyzed: int
    suspicious_items: int

class KeyloggerDetector:
    def __init__(self):
        self.items: list[TelemetryItem] = []

    def reset(self):
        self.items.clear()

    def add_item(self, item: TelemetryItem) -> DetectionResult:
        self.items.append(item)
        return self.evaluate()

    def evaluate(self) -> DetectionResult:
        if not self.items:
            return DetectionResult(0, "NORMAL", [], 0, 0)

        all_findings = []
        suspicious_items = 0

        for item in self.items:
            findings = analyze_item(item)
            all_findings.extend(
                Finding(
                    title=f"{item.name}: {finding.title}",
                    detail=finding.detail,
                    weight=finding.weight,
                )
                for finding in findings
            )
            if findings:
                suspicious_items += 1

        # Keep the score bounded and avoid double-counting identical rule signals
        # across a large process list.
        unique_keys = set()
        score = 0
        unique_findings = []

        for finding in all_findings:
            key = (finding.title, finding.detail)
            if key in unique_keys:
                continue
            unique_keys.add(key)
            unique_findings.append(finding)
            score += finding.weight

        if suspicious_items >= 3:
            score += 10
            unique_findings.append(Finding(
                "Multiple suspicious items",
                "Several telemetry items contain security-relevant indicators.",
                10,
            ))

        score = min(100, score)

        if score >= 80:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 40:
            severity = "MEDIUM"
        elif score >= 20:
            severity = "LOW"
        else:
            severity = "NORMAL"

        return DetectionResult(
            score=score,
            severity=severity,
            findings=unique_findings,
            items_analyzed=len(self.items),
            suspicious_items=suspicious_items,
        )
