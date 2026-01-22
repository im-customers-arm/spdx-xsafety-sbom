# SPDX Safety Profile Extension Specification

**Version:** 2.1.0
**Status:** Stable
**Namespace:** `https://example.org/spdx-extensions/xSafety/`
**Prefix:** `xSafety`

## Overview

This specification defines the xSafety extension for SPDX 3.0.1, enabling documentation of safety-critical systems metadata for functional safety standards:

- **ISO 26262** - Automotive Functional Safety
- **DO-178C** - Aerospace Software Considerations
- **IEC 61508** - Functional Safety of E/E/PE Systems
- **IEC 62304** - Medical Device Software
- **EN 50128** - Railway Applications

## Design Philosophy: Core-First Approach

**Version 2.1.0 adopts a "core-first" design philosophy** that maximizes use of SPDX 3.0.1 core capabilities before introducing custom extensions. This approach:

- **Reduces complexity**: Custom properties only where domain-specific semantics are required
- **Improves interoperability**: Standard SPDX tools can process safety-related SBOMs without safety profile knowledge
- **Enables querying**: Use `primaryPurpose` vocabulary to find requirements, tests, and evidence
- **Future-proofs**: Benefits from core SPDX specification evolution

### Core SPDX 3.0.1 Properties Used by Safety Profile

| Core Property | Safety Profile Usage |
|---------------|---------------------|
| `Element.name` | Artifact ID (HAZ-001, SSR-008, TC-042, EVID-015) |
| `Element.description` | Full text (hazard statement, requirement text, test objective) |
| `Element.comment` | Supporting information (rationale, verification approach) |
| `Element.primaryPurpose` | Semantic typing (`requirement`, `test`, `evidence`) |
| `Relationship.hasSpecification` | Package/File → Requirement (component implements requirement) |
| `Relationship.hasTestCase` | Requirement → Test case traceability |
| `Relationship.hasEvidence` | Requirement/Test → Evidence traceability |
| `Relationship.descendantOf` | Parent-child requirement hierarchy (TSR → SSR) |
| `Relationship.testedOn` | Test → Component (test executed on component) |

**Extension Properties**: Only safety-specific metadata (ASIL levels, HARA ratings, requirement classification)

---

## Extension Classes

### HazardExtension

**Summary:** Extension documenting ISO 26262 hazard analysis and risk assessment (HARA) data.

**Parent Class:** `Extension/Extension`

**URI:** `https://example.org/spdx-extensions/xSafety/HazardExtension`

#### Properties

| Property | Type | Min | Max | Description |
|----------|------|-----|-----|-------------|
| severity | SeverityLevel | 0 | 1 | ISO 26262 severity rating (S0-S3) |
| exposure | ExposureLevel | 0 | 1 | ISO 26262 exposure rating (E0-E4) |
| controllability | ControllabilityLevel | 0 | 1 | ISO 26262 controllability rating (C0-C3) |
| safetyIntegrityLevel | SafetyIntegrityLevel | 0 | 1 | ASIL or SIL classification |

#### Usage

```json
{
  "@type": "Bundle",
  "spdxId": "urn:spdx:example:element-HAZ-001",
  "name": "HAZ-001",
  "description": "Missing CAM message not detected",
  "primaryPurpose": "requirement",
  "extension": [{
    "type": "xSafety:HazardExtension",
    "xSafety:severity": "s2",
    "xSafety:exposure": "e3",
    "xSafety:controllability": "c2",
    "xSafety:safetyIntegrityLevel": "asilB"
  }]
}
```

---

### SafetyGoalExtension

**Summary:** Extension documenting ISO 26262 safety goals derived from hazards.

**Parent Class:** `Extension/Extension`

**URI:** `https://example.org/spdx-extensions/xSafety/SafetyGoalExtension`

#### Properties

| Property | Type | Min | Max | Description |
|----------|------|-----|-----|-------------|
| safetyIntegrityLevel | SafetyIntegrityLevel | 1 | 1 | ASIL or SIL classification |

#### Usage

```json
{
  "@type": "Bundle",
  "spdxId": "urn:spdx:example:element-SG-001",
  "name": "SG-001",
  "description": "Ensure CAM message reception is monitored with timeout detection",
  "primaryPurpose": "requirement",
  "extension": [{
    "type": "xSafety:SafetyGoalExtension",
    "xSafety:safetyIntegrityLevel": "asilB"
  }]
}
```

---

### SafetyExtension

**Summary:** Extension providing safety classification metadata for any Element.

**Parent Class:** `Extension/Extension`

**URI:** `https://example.org/spdx-extensions/xSafety/SafetyExtension`

#### Properties

| Property | Type | Min | Max | Description |
|----------|------|-----|-----|-------------|
| safetyRelevant | xsd:boolean | 0 | 1 | Whether this element is safety-relevant |
| safetyIntegrityLevel | SafetyIntegrityLevel | 0 | 1 | ASIL or SIL classification |
| complianceStatus | ComplianceStatus | 0 | 1 | Current compliance state |

#### Usage

```json
{
  "spdxId": "urn:spdx:example:package-brake-controller",
  "@type": "software_Package",
  "name": "brake-controller",
  "primaryPurpose": "application",
  "extension": [{
    "type": "xSafety:SafetyExtension",
    "xSafety:safetyRelevant": true,
    "xSafety:safetyIntegrityLevel": "asilD",
    "xSafety:complianceStatus": "compliant"
  }]
}
```

---

### SafetyRequirementExtension

**Summary:** Extension documenting safety requirement classification.

**Parent Class:** `Extension/Extension`

**URI:** `https://example.org/spdx-extensions/xSafety/SafetyRequirementExtension`

#### Properties

| Property | Type | Min | Max | Description |
|----------|------|-----|-----|-------------|
| requirementType | SafetyRequirementType | 1 | 1 | Classification level (TSR, SSR, etc.) |
| safetyIntegrityLevel | SafetyIntegrityLevel | 0 | 1 | ASIL or SIL classification |

#### Usage

```json
{
  "@type": "Bundle",
  "spdxId": "urn:spdx:example:element-SSR-008",
  "name": "SSR-008",
  "description": "cam-service shall schedule a per-event timer that triggers a safety violation if the next event is not received within 1000ms",
  "primaryPurpose": "requirement",
  "extension": [{
    "type": "xSafety:SafetyRequirementExtension",
    "xSafety:requirementType": "softwareSafetyRequirement",
    "xSafety:safetyIntegrityLevel": "asilB"
  }]
}
```

---

### SafetyEvidenceExtension

**Summary:** Extension documenting safety evidence/verification results.

**Parent Class:** `Extension/Extension`

**URI:** `https://example.org/spdx-extensions/xSafety/SafetyEvidenceExtension`

#### Properties

| Property | Type | Min | Max | Description |
|----------|------|-----|-----|-------------|
| evidenceType | EvidenceType | 1 | 1 | Classification of evidence |
| evidenceResult | EvidenceResult | 0 | 1 | Outcome |
| validUntil | xsd:dateTime | 0 | 1 | Expiration date |

#### Usage

```json
{
  "@type": "software_File",
  "spdxId": "urn:spdx:example:evidence-EVID-015",
  "name": "EVID-015",
  "description": "Test execution results for TC-042",
  "primaryPurpose": "evidence",
  "extension": [{
    "type": "xSafety:SafetyEvidenceExtension",
    "xSafety:evidenceType": "testResult",
    "xSafety:evidenceResult": "pass"
  }]
}
```

---

### SafetyTestExtension

**Summary:** Extension documenting test classification and details.

**Parent Class:** `Extension/Extension`

**URI:** `https://example.org/spdx-extensions/xSafety/SafetyTestExtension`

#### Properties

| Property | Type | Min | Max | Description |
|----------|------|-----|-----|-------------|
| testType | TestType | 1 | 1 | Classification of test |
| testSteps | xsd:string | 0 | * | Ordered list of test execution steps |
| expectedResult | xsd:string | 0 | 1 | Expected outcome description |
| safetyIntegrityLevel | SafetyIntegrityLevel | 0 | 1 | ASIL or SIL classification |

#### Usage

```json
{
  "@type": "Bundle",
  "spdxId": "urn:spdx:example:element-TC-042",
  "name": "TC-042",
  "description": "Verify timer triggers on missing CAM message",
  "primaryPurpose": "test",
  "extension": [{
    "type": "xSafety:SafetyTestExtension",
    "xSafety:testType": "integrationTest",
    "xSafety:safetyIntegrityLevel": "asilB"
  }]
}
```

---

## Vocabularies

### SafetyIntegrityLevel

**URI:** `https://example.org/spdx-extensions/xSafety/SafetyIntegrityLevel`

| Entry | Description |
|-------|-------------|
| asilA | ISO 26262 ASIL A |
| asilB | ISO 26262 ASIL B |
| asilC | ISO 26262 ASIL C |
| asilD | ISO 26262 ASIL D |
| qm | ISO 26262 Quality Management (non-safety) |
| sil1 | IEC 61508 SIL 1 |
| sil2 | IEC 61508 SIL 2 |
| sil3 | IEC 61508 SIL 3 |
| sil4 | IEC 61508 SIL 4 |
| dalA | DO-178C Design Assurance Level A |
| dalB | DO-178C Design Assurance Level B |
| dalC | DO-178C Design Assurance Level C |
| dalD | DO-178C Design Assurance Level D |

---

### SeverityLevel

**URI:** `https://example.org/spdx-extensions/xSafety/SeverityLevel`

| Entry | Description |
|-------|-------------|
| s0 | No injuries |
| s1 | Light and moderate injuries |
| s2 | Severe and life-threatening injuries (survival probable) |
| s3 | Life-threatening injuries (survival uncertain), fatal injuries |

---

### ExposureLevel

**URI:** `https://example.org/spdx-extensions/xSafety/ExposureLevel`

| Entry | Description |
|-------|-------------|
| e0 | Incredible |
| e1 | Very low probability |
| e2 | Low probability |
| e3 | Medium probability |
| e4 | High probability |

---

### ControllabilityLevel

**URI:** `https://example.org/spdx-extensions/xSafety/ControllabilityLevel`

| Entry | Description |
|-------|-------------|
| c0 | Controllable in general |
| c1 | Simply controllable |
| c2 | Normally controllable |
| c3 | Difficult to control or uncontrollable |

---

### SafetyRequirementType

**URI:** `https://example.org/spdx-extensions/xSafety/SafetyRequirementType`

| Entry | Description |
|-------|-------------|
| technicalSafetyRequirement | Technical Safety Requirement (TSR) |
| softwareSafetyRequirement | Software Safety Requirement (SSR) |
| hardwareSafetyRequirement | Hardware Safety Requirement (HSR) |
| functional | Functional requirement |

---

### ComplianceStatus

**URI:** `https://example.org/spdx-extensions/xSafety/ComplianceStatus`

| Entry | Description |
|-------|-------------|
| compliant | Fully compliant with requirements |
| partiallyCompliant | Partially compliant, deviations documented |
| nonCompliant | Not compliant |
| underReview | Compliance under review |
| notApplicable | Compliance not applicable |
| noAssertion | No assertion made about compliance |

---

### TestType

**URI:** `https://example.org/spdx-extensions/xSafety/TestType`

| Entry | Description |
|-------|-------------|
| unitTest | Unit-level test |
| integrationTest | Integration test |
| systemTest | System-level test |
| validationTest | Validation test |
| regressionTest | Regression test |
| faultInjectionTest | Fault injection test |
| hardwareInLoopTest | Hardware-in-the-loop test (HIL) |
| softwareInLoopTest | Software-in-the-loop test (SIL) |
| modelInLoopTest | Model-in-the-loop test (MIL) |

---

### EvidenceType

**URI:** `https://example.org/spdx-extensions/xSafety/EvidenceType`

| Entry | Description |
|-------|-------------|
| testReport | Test report document |
| testResult | Automated test result |
| reviewReport | Review/audit report |
| analysisReport | Analysis report |
| certificationReport | Certification report |
| auditReport | External audit report |
| traceabilityMatrix | Traceability matrix |
| complianceStatement | Compliance statement |

---

### EvidenceResult

**URI:** `https://example.org/spdx-extensions/xSafety/EvidenceResult`

| Entry | Description |
|-------|-------------|
| pass | Test/review passed |
| fail | Test/review failed |
| partial | Partial pass with deviations |
| inconclusive | Result inconclusive |
| notApplicable | Not applicable |

---

## Modeling Safety Traceability

Safety traceability is modeled using **standard SPDX 3.0.1 core relationships**:

| Relationship | From | To | Description |
|-------------|------|-----|-------------|
| `descendantOf` | Safety Goal | Hazard | Safety goal derived from hazard |
| `descendantOf` | TSR | Safety Goal | TSR derived from safety goal |
| `descendantOf` | SSR | TSR | SSR derived from TSR |
| `hasSpecification` | SSR | SWA | Requirement has architecture spec |
| `hasTestCase` | SSR | Test Case | Requirement has test case |
| `hasEvidence` | Test Case | Evidence | Test has evidence |
| `testedOn` | Bundle | File | Requirement tested on source file |

---

## References

- [SPDX 3.0.1 Specification](https://spdx.github.io/spdx-spec/v3.0.1/)
- [ISO 26262:2018 - Road vehicles - Functional safety](https://www.iso.org/standard/68383.html)
- [IEC 61508 - Functional Safety](https://webstore.iec.ch/publication/5515)
- [DO-178C - Software Considerations in Airborne Systems](https://www.rtca.org/products/do-178c/)
