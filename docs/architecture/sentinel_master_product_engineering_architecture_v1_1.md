**SENTINEL**

**PROTECTIVE OPERATING SYSTEM**

Master Product, Security, Intelligence & Engineering Architecture

**Detect \| Understand \| Correlate \| Communicate \| Decide \| Coordinate \| Respond \| Pursue \| Protect \| Prove**

MASTER DESIGN • VERSION 1.1 • AUGUST 2026

Concept architecture for lawful high-security protective operations

# Document Control

| **Item**        | **Definition**                                                                                                                                                                                      |
|-----------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Product         | Sentinel Protective Operating System                                                                                                                                                                |
| Document        | Master Product, Security, Intelligence & Engineering Architecture                                                                                                                                   |
| Version         | 1.1                                                                                                                                                                                                 |
| Status          | Updated architecture baseline for product planning and phased implementation; includes dedicated Guest Protection and hospitality/visitor deployment architecture                                                                                                                                |
| Primary purpose | Define what Sentinel is, why it exists, how it operates, how it should be built, and how its capabilities are governed and tested.                                                                  |
| Audience        | Product leadership, security architects, software engineers, AI/ML engineers, mobile engineers, edge/video engineers, operations leaders, legal/privacy reviewers and authorised security partners. |
| Design rule     | High-consequence actions require explicit policy authority. Sentinel may analyse aggressively but must not autonomously cross legal or safety boundaries.                                           |

## Source and standards basis

This design incorporates the earlier visitor-safety concepts that were discussed for the Yoruba Heritage Park project, but Sentinel is defined here as an independent platform with a substantially broader architecture. Those visitor-safety concepts are now formalised as **Sentinel Guest Protection**, a dedicated hospitality, tourism, campus, event, healthcare and public-facing protection profile that can operate through mobile web, QR, NFC, digital credentials, optional applications and organisation-configured Whisper intents. The engineering recommendations are also informed by current primary standards and guidance from NIST, MITRE, ONVIF, the IETF, CISA and the Nigeria Data Protection Commission. A standards appendix appears at the end of this document.

## Non-negotiable terminology

- Controlled Reality is the preferred term for environments intentionally constructed so an adversary encounters assets, information and workflows that are operationally real within a defender-controlled boundary.

- Whisper is a configurable multimodal human-intent system. Its secret or discreet signals are never universal hard-coded commands.

- Pursuit means lawful tracking, correlation, intelligence acquisition, evidence preservation and authority handoff. It does not mean autonomous unauthorised intrusion into external systems.

- Identity conclusions are graded by confidence and verification status. A biometric candidate is not treated as proof of criminal identity.

- Threat states describe current evidence and behaviour. Sentinel does not permanently label a person as inherently friendly or hostile.

## Table of Contents

**Part I — Product Foundation**

**Part II — Operational Platform**

**Part III — Adversarial Preparedness & Scenario Playbooks**

**Part IV — Engineering & Build Architecture**

**Part V — Delivery, Assurance & Operations**

**Appendices — Schemas, Metrics, Repository Structure & Standards**

**Supplement — Detailed Engineering Implementation Blueprint**

**PART I — PRODUCT FOUNDATION**

What Sentinel is, why it exists, and the principles that govern it.

# 1. Executive Definition

Sentinel is a distributed protective operating system designed to protect people, facilities, organisations, territories, vehicles, digital infrastructure and critical assets. It combines physical security, cyber defence, artificial intelligence, field operations, intelligence correlation, evidence preservation and continuous adversarial testing into one coherent operational platform.

The product is built around a simple strategic idea: security systems fail when they collect signals without understanding the relationship between them. Sentinel therefore treats cameras, access control, field observations, mobile devices, sensors, cyber telemetry, open-source intelligence and historical incidents as parts of one operational picture.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Core operating doctrine</strong><br />
Detect. Understand. Correlate. Communicate. Decide. Coordinate. Respond. Pursue. Protect. Prove.</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

## 1.1 The nine questions Sentinel must answer continuously

1.  What is happening?

2.  Where is it happening?

3.  Who or what is involved?

4.  Is the activity expected, anomalous, suspicious, dangerous or verified as a threat?

5.  What independent evidence supports or contradicts that conclusion?

6.  Who needs to know?

7.  What actions are authorised now?

8.  Is the response actually protecting the mission?

9.  Can Sentinel later prove what happened and why actions were taken?

# 2. Why Sentinel Exists

Most security environments are fragmented. CCTV, access control, guards, fire systems, vehicle records, cyber monitoring, visitor systems, radios, messaging tools and incident reports often operate separately. The organisation may own significant security hardware yet still lack an integrated understanding of what is happening.

Sentinel exists to solve that coordination problem. Its central value is not another detector. Its value is the ability to convert many independent observations into a structured threat assessment and then into an authorised, measurable response.

> CAMERA + ACCESS + FIELD + SENSOR + CYBER + CONTEXT  
> ↓  
> SENTINEL FUSION  
> ↓  
> THREAT ASSESSMENT  
> ↓  
> INCIDENT  
> ↓  
> RESPONSE PLAYBOOK

## 2.1 Defensive asymmetry

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>The Asymmetry Doctrine</strong><br />
A defender can succeed repeatedly and still lose through one sufficiently damaging failure. Every serious attack must therefore produce three outcomes: protection of the immediate target, intelligence about the adversary and method, and evidence that supports lasting disruption through competent authorities.</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

This doctrine changes the success metric from “attack blocked” to “attack blocked, adversary understood, exploited path hardened, return made easier to detect, and evidence preserved.”

# 3. Mission and Scope

## 3.1 Mission

Sentinel provides continuous protective awareness by combining humans, sensors and intelligent software into a coordinated security system capable of detecting threats early, understanding context, communicating discreetly, coordinating response, pursuing high-threat cases through lawful intelligence and preserving reliable evidence.

## 3.2 In scope

- Real-time command and control for authorised security operations.

- CCTV and IP-video integration.

- Behaviour, movement, object and event analytics.

- Field operative applications and discreet communications.

- Protected-user mobile functions.

- Guest and visitor protection for hospitality, tourism, events, campuses, healthcare and other public-facing sites, including no-install mobile-web access, digital credentials, guardian journeys, discreet assistance and location-aware response.

- Incident orchestration and playbooks.

- Cross-camera and vehicle tracking.

- Candidate identity correlation where legally authorised.

- Open-source threat intelligence and isolated high-risk-source monitoring.

- Cyber defence, threat hunting and platform self-protection.

- Controlled Reality environments on defender-owned or expressly authorised infrastructure.

- Forensic readiness, evidence integrity and case development.

- Continuous adversarial simulation, scenario generation and vulnerability assurance.

- Multi-site operations and edge resilience.

## 3.3 Explicit boundaries

- Sentinel does not autonomously intrude into systems it is not authorised to access.

- Sentinel does not treat biometric similarity or an AI score as criminal guilt.

- Sentinel does not bypass private accounts or protected records merely because those records could be useful.

- Direct integration with public security, fire or medical agencies must use officially authorised channels, contractual monitoring arrangements or lawful authority appropriate to the jurisdiction.

- High-consequence physical or cyber actions must pass the Sentinel Constitution and the configured organisational policy.

- Critical biometric, tracking and investigative features require privacy, legal and operational review before production activation.

# 4. Founding Doctrines

## Intelligence Before Automation

Evidence, context, confidence, policy and authority come before consequential action.

## Multi-Signal Confirmation

One detector should rarely control a major security response. Independent signals are deliberately combined and contradictory evidence is actively sought.

## Silent When Necessary

The system must be able to coordinate protection without revealing to an aggressor that detection has occurred.

## Sentinel Has Memory

Every serious adversary, incident, failure and successful defence becomes structured institutional knowledge used to recognise return and strengthen future tests.

## Controlled Reality

When policy permits, a detected adversary may encounter a defender-controlled environment designed to protect real assets while revealing intent, methods and indicators.

## Crucible Doctrine

Sentinel must not wait for an adversary to demonstrate that a defence can fail. It continuously challenges its own assumptions and constructs plausible attack paths in authorised environments.

## Evidence Is Native

Forensic readiness is designed into the platform rather than added after an incident.

## Mission Over Uptime

A healthy server is not the same as a protected mission. Sentinel measures whether critical protective functions remain achievable.

## The System May Be Wrong

Uncertainty, contradictory evidence and independent challenge are explicit components of decision-making.

# 5. The Three-Brain Governance Model

Sentinel should never give one reasoning system unlimited authority over sensors, people, identity, cyber controls and response. Its decision architecture therefore separates three functions.

| **Authority**         | **Question**                                                   | **Function**                                                                                                                                          |
|-----------------------|----------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Sentinel Fusion       | What is probably happening?                                    | Correlates observations, context and historical intelligence into hypotheses and threat assessments.                                                  |
| Sentinel Adversary    | How might that conclusion be wrong, manipulated or incomplete? | Actively searches for contradictory evidence, blind spots, spoofing, alternate hypotheses and untested assumptions.                                   |
| Sentinel Constitution | What are we authorised to do?                                  | Applies immutable and versioned policy constraints, approval requirements, legal boundaries and safety controls before consequential actions execute. |

> OBSERVATION  
> ↓  
> FUSION ASSESSMENT  
> ↓  
> ADVERSARY CHALLENGE  
> ↓  
> CONFIDENCE + UNCERTAINTY  
> ↓  
> CONSTITUTION + ORGANISATION POLICY  
> ↓  
> COMMAND / RESPONSE / PURSUIT

## 5.1 Sentinel Constitution

The Constitution is a small, hardened policy layer that neither AI models nor ordinary administrators can silently rewrite. Critical rules are versioned, signed, audited and subject to controlled approval. Examples include what actions require two-person approval, when location may be collected, how Controlled Reality can be activated, whether an external agency connector may be used, and which categories of Crucible test may execute in production.

## 5.2 Decision Ledger

Every serious decision stores the information available at that moment, the model and rule versions used, evidence supporting and contradicting the decision, confidence values, the applicable policy version, approvals, resulting action and later outcome. The ledger makes post-incident review, legal explanation, model evaluation and regression testing possible.

**PART II — OPERATIONAL PLATFORM**

Detailed functions of each Sentinel subsystem and how they work together.

# 6. Product Module Map

| **Module**                  | **Primary responsibility**                                                                         |
|-----------------------------|----------------------------------------------------------------------------------------------------|
| Sentinel Command            | Control-room interface and incident coordination.                                                  |
| Sentinel Vision             | Video ingestion, analytics, tracking and camera orchestration.                                     |
| Sentinel Fusion             | Multi-source correlation, confidence, threat state and hypothesis management.                      |
| Sentinel Response           | Playbooks, dispatch, escalation and incident orchestration.                                        |
| Sentinel Field              | Field operative application, patrols, tasks and evidence capture.                                  |
| Sentinel Whisper            | Organisation-configured discreet multimodal intent and protocol triggering.                        |
| Sentinel Pursuit            | High-threat tracking, intelligence correlation and continuing case pursuit.                        |
| Sentinel Identity           | Candidate identity analysis and verification workflow.                                             |
| Sentinel Vehicle            | Vehicle detection, tracking, association and route reconstruction.                                 |
| Sentinel Access             | Credentials, visitors, doors, gates, access anomalies and physical identity context.               |
| Sentinel Perimeter          | Boundary protection, restricted zones and perimeter sensing.                                       |
| Sentinel Edge               | On-site processing, resilience, device integration and offline operation.                          |
| Sentinel Mobile             | Protected-user application and authorised safety functions.                                        |
| Sentinel Guest Protection   | Hospitality and visitor protection through mobile web, QR/NFC, digital credentials, guardian journeys, discreet assistance and site-aware response. |
| Sentinel OpenIntel          | Lawful public-source intelligence acquisition and correlation.                                     |
| Sentinel DarkWatch          | Isolated collection from high-risk intelligence sources, including Tor-based sources where lawful. |
| Sentinel Controlled Reality | Defender-controlled environments used to protect real assets and study adversary behaviour.        |
| Sentinel Cyber              | Cyber event detection, threat hunting and cyber incident management.                               |
| Sentinel Shield             | Platform self-protection, identity, device trust, integrity and quarantine.                        |
| Sentinel Crucible           | Continuous security testing, scenario execution and attack-path validation.                        |
| Sentinel Chimera            | Novel attack hypothesis generation and attack composition.                                         |
| Sentinel Case               | Case construction, provenance, hypothesis management and authority handoff.                        |
| Sentinel Evidence           | Immutable evidence vault, chain of custody and forensic export.                                    |
| Sentinel Intelligence       | Trends, campaign memory, risk analytics and performance.                                           |
| Sentinel Mission Assurance  | Determines whether protective missions remain achievable under current failures and attacks.       |
| Sentinel Black Box          | Independently protected operational recorder for high-value system events and decisions.           |

# 7. End-to-End Functional Architecture

> PEOPLE / GUESTS / CAMERAS / VEHICLES / ACCESS / SENSORS / CYBER / INTELLIGENCE  
> ↓  
> INGESTION LAYER  
> ↓  
> NORMALISED EVENT BUS  
> ↓  
> SENTINEL FUSION  
> ↙ ↓ ↘  
> THREAT STATE ADVERSARY CASEGRAPH  
> \\ \| /  
> CONSTITUTION  
> ↓  
> INCIDENT  
> ↓  
> COMMAND + RESPONSE + FIELD + PURSUIT  
> ↓  
> EVIDENCE + DECISION LEDGER  
> ↓  
> INTELLIGENCE + CRUCIBLE LEARNING

## 7.1 Event-first architecture

Every meaningful observation enters Sentinel as a normalised event. This keeps cameras, sensors, field reports and cyber tools from creating separate alarm universes. Events are immutable statements about what a source observed. Conclusions are produced later by Fusion.

# 8. Site, Asset and Digital-Twin Model

> ORGANISATION  
> └─ SITE  
> ├─ BUILDING / OUTDOOR AREA  
> │ ├─ FLOOR  
> │ │ ├─ ZONE  
> │ │ ├─ ROOM  
> │ │ └─ ACCESS POINT  
> │ ├─ CAMERA  
> │ ├─ SENSOR  
> │ ├─ CHECKPOINT  
> │ ├─ SAFE / ASSEMBLY AREA  
> │ └─ RESPONSE POINT  
> └─ PERIMETER / ROUTES

The digital twin is not decorative mapping. It gives Fusion spatial context: which camera can see a corridor, which responder is nearest, which doors connect two zones, what route a vehicle can take, what protective objective loses coverage when a camera fails, and which sensors are independent versus sharing a common dependency.

# 9. Sentinel Command

## 9.1 Purpose

Command is the operational workspace for authorised controllers. During a critical event an operator should not navigate across numerous pages. The incident, map, relevant cameras, field teams, communications, evidence and playbook state should be visible from a single operational workspace.

> ┌────────────────────────────────────────────────────┐  
> │ SITE / SHIFT / MISSION ASSURANCE / SYSTEM HEALTH │  
> ├──────────────┬──────────────────┬──────────────────┤  
> │ INCIDENTS │ │ CAMERAS │  
> │ ALERT QUEUE │ LIVE MAP │ FIELD UNITS │  
> │ PLAYBOOKS │ │ ASSET HEALTH │  
> ├──────────────┴──────────────────┴──────────────────┤  
> │ TIMELINE \| COMMANDS \| WHISPER \| EVIDENCE \| CASE │  
> └────────────────────────────────────────────────────┘

## 9.2 Core functions

- Prioritised incident queue with severity, confidence and mission impact.

- Live site map and digital-twin navigation.

- Automatic surfacing of relevant camera streams.

- Field team locations, states, skills, assignments and estimated arrival.

- Playbook actions with required approvals clearly marked.

- Whisper communications and acknowledgements.

- Timeline of events, decisions and responses.

- Case and evidence links.

- Mission-assurance state and degraded capabilities.

- External escalation state and delivery receipts.

# 10. Sentinel Vision

## 10.1 Camera integration

Sentinel should prioritise ONVIF Profile T for advanced IP-video functions and Profile M for analytics metadata and events. Profile T supports advanced streaming, metadata, motion/tamper events, PTZ and related video controls; Profile M standardises analytics metadata and events. RTSP and manufacturer-specific adapters are secondary integration paths. Device conformance must be verified rather than assumed.

## 10.2 Vision pipeline

> CAMERA / NVR  
> ↓  
> SENTINEL EDGE  
> ↓  
> DECODE + NORMALISE  
> ↓  
> OBJECT DETECTION  
> ↓  
> TRACKING  
> ↓  
> BEHAVIOUR / ZONE ANALYTICS  
> ↓  
> EVENT GENERATION  
> ├─ METADATA → EVENT BUS  
> └─ RELEVANT VIDEO → EVIDENCE BUFFER / COMMAND

## 10.3 Detection families

| **Family**          | **Examples**                                                                                     | **Operational use**                                 |
|---------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------------------|
| Objects             | Person, vehicle, selected equipment, configured threat-like objects                              | Tracking, zone logic, incident context.             |
| Movement            | Entry, exit, line crossing, direction, speed anomaly, running, convergence                       | Perimeter and behavioural context.                  |
| Area                | Loitering, restricted-zone presence, crowding, after-hours occupancy                             | Contextual risk and operator review.                |
| Violence indicators | Physical struggle, repeated striking patterns, dragging, aggressive pursuit, person knocked down | Temporal event supplied to Fusion, not final truth. |
| Health/safety       | Fall or collapse indicators, immobility, crowd formation around person                           | Medical-response context.                           |
| Camera integrity    | Obstruction, scene change, freeze, focus loss, repositioning, stream degradation                 | Shield and Mission Assurance.                       |

## 10.4 Violence analysis

Violence analysis must operate on short temporal sequences rather than a single frame. The output is a structured event such as “possible physical violence, confidence 0.82, duration 2.4 seconds, tracks P281 and P294.” Fusion then considers location, access events, field reports, threat-object events and other evidence.

## 10.5 Threat-like object analysis

Potential weapon-related detection must preserve uncertainty. A model result such as “firearm-like object, 0.89” is evidence, not a declaration of guilt. High-consequence action should require configured corroboration, operator verification or other authorised confirmation depending on policy.

# 11. Sentinel Fusion

## 11.1 Purpose

Fusion is the intelligence core. It receives independent events and asks whether they describe the same developing situation. It considers time, location, source trust, model confidence, historical context, access state, human reports, active campaigns and contradictory evidence.

## 11.2 Threat-state model

| **State**                      | **Meaning**                                           | **Typical system behaviour**                      |
|--------------------------------|-------------------------------------------------------|---------------------------------------------------|
| STATE 0 — NORMAL               | No meaningful abnormality.                            | Routine monitoring.                               |
| STATE 1 — OBSERVE              | Weak anomaly or incomplete evidence.                  | Increase analysis, preserve context.              |
| STATE 2 — SUSPICIOUS           | Evidence requires operator attention.                 | Create alert, correlate nearby sources.           |
| STATE 3 — PROBABLE THREAT      | Multiple indicators support a threat hypothesis.      | Escalate, prepare response options.               |
| STATE 4 — VERIFIED THREAT      | Strong multi-source or authorised human confirmation. | Execute approved high-threat playbook.            |
| STATE 5 — CRITICAL LIFE-SAFETY | Immediate serious harm is occurring or imminent.      | Prioritised protective coordination under policy. |

## 11.3 Confidence is separate from severity

Sentinel stores at least four distinct values: detection confidence, threat probability, potential impact and operational severity. A highly confident minor access anomaly may be low severity, while a moderately confident possible armed attack may demand immediate review because potential impact is extreme.

## 11.4 Contradictory-evidence engine

Fusion must actively search for observations that weaken its current hypothesis. This is a first-class feature, not a courtesy. For example, if a biometric candidate appears to match a person but verified access and device evidence strongly places that person elsewhere, the identity hypothesis must lose confidence.

# 12. Sentinel Response

## 12.1 Incident object

> INCIDENT  
> - identity and site  
> - incident type and severity  
> - threat state and confidence  
> - response mode  
> - commander and assigned teams  
> - related events / tracks / vehicles  
> - playbook version  
> - timeline  
> - evidence references  
> - approvals  
> - external notifications  
> - closure and post-incident review

## 12.2 Severity

| **Level**           | **Meaning**                                                            |
|---------------------|------------------------------------------------------------------------|
| SEV-1 CRITICAL      | Immediate threat to life, major protected asset or mission continuity. |
| SEV-2 HIGH          | Serious threat requiring rapid operational response.                   |
| SEV-3 MODERATE      | Security condition requiring investigation or intervention.            |
| SEV-4 LOW           | Operational issue requiring attention.                                 |
| SEV-5 INFORMATIONAL | Recorded event without immediate response requirement.                 |

## 12.3 Response modes

| **Mode** | **Purpose**                                                                                                             |
|----------|-------------------------------------------------------------------------------------------------------------------------|
| STANDARD | Visible alerts and ordinary communications are acceptable.                                                              |
| DISCREET | Response deliberately minimises visible security activity.                                                              |
| SILENT   | The local environment should not reveal that the threat has been detected or that protective coordination is occurring. |

# 13. Sentinel Field

Field personnel are active intelligence and response nodes. The field application supports guards, patrol officers, supervisors, medical responders, drivers, investigators and specialist teams.

| **Field state** | **Meaning**                                                     |
|-----------------|-----------------------------------------------------------------|
| AVAILABLE       | Ready for assignment.                                           |
| PATROL          | Executing scheduled route or task.                              |
| OBSERVING       | Maintaining discreet observation.                               |
| RESPONDING      | Moving toward assigned incident.                                |
| ON SCENE        | Operating at incident location.                                 |
| NEED SUPPORT    | Additional resources requested.                                 |
| COMPROMISED     | Possible coercion, duress or inability to communicate normally. |
| OFF DUTY        | Not operationally available.                                    |

## 13.1 Core field functions

- Incident dispatch and acknowledgement.

- Turn-by-turn or map-based navigation.

- Need-to-know incident brief.

- Secure text, voice note and approved media.

- Whisper signals.

- Patrol routes and checkpoint verification.

- Field observation sessions.

- Evidence capture with automatic time/location metadata.

- Backup or specialist-team request.

- Welfare check and device health.

- Offline queueing and later synchronisation.

# 14. Sentinel Whisper — Configurable Multimodal Human Intent

Whisper is not a static secret-command list. Each organisation defines its own discreet signals, authorised users, operational contexts, confidence thresholds and the protocol to execute. The same organisation can maintain different signal sets for sites, teams, shifts or clearance levels.

## 14.1 Supported modalities

| **Modality**    | **Examples**                                                   | **Security considerations**                            |
|-----------------|----------------------------------------------------------------|--------------------------------------------------------|
| Spoken phrase   | Organisation-defined ordinary phrase or code phrase            | Voice quality, replay resistance, role/context checks. |
| Sound           | Knock pattern, tone, whistle, configured acoustic signature    | Environmental false triggers, replay resistance.       |
| Gesture         | Hand or body signal recognised by authorised cameras/device    | Liveness, camera trust, visibility and site context.   |
| Motion sequence | Movement sequence over time rather than a single pose          | Temporal recognition and accidental similarity.        |
| Device action   | Hardware button, touch sequence, headset or mobile action      | Device identity and anti-replay.                       |
| Wearable action | Watch/button interaction or haptic response                    | Wearable identity, pairing and compromise state.       |
| Combined        | Two or more modalities under a defined sequence or time window | Recommended for high-consequence intents.              |

## 14.2 Whisper Studio

Whisper Studio is the administrative environment where authorised personnel create, test, approve, rotate and retire signals. A signal object must be versioned and separate from the response protocol it invokes.

> WHISPER SIGNAL WS-0041  
> Name: Field Assistance Alpha  
> Scope: Example Site / Security Level 2+  
> Inputs: Gesture G-12 OR (Phrase P-04 + Wearable Action W-02)  
> Valid context: on-duty, authorised zones  
> Required confidence: HIGH  
> Response mode: SILENT  
> Intent: DISCREET_ASSISTANCE_REQUIRED  
> Protocol: RP-SEC-011  
> Confirmation: haptic  
> Version: 7  
> Status: ACTIVE

## 14.3 Combination logic

- A

- A AND B

- A OR B

- A followed by B within a configured time window

- A repeated N times

- A only when context X is true

- A without expected companion signal C

- A plus verified authorised-device proximity

## 14.4 Anti-spoofing

Whisper must anticipate recorded audio, displayed gestures, stolen wearables, cloned devices, synthetic voice, video replay and compromised cameras. Confidence may therefore combine signal recognition with device identity, user role, location, time, liveness, camera continuity, wearable proximity and signal freshness.

## 14.5 Lifecycle

> DRAFT → SIMULATION → FALSE-POSITIVE TEST → ANTI-SPOOF TEST → FIELD DRILL → APPROVAL → ACTIVE → ROTATED / RETIRED

Crucible continuously tests active Whisper configurations for accidental triggers and spoofability. Sentinel may recommend threshold changes but must not silently redefine what an organisation-defined human signal means.

# 15. Sentinel Pursuit

Pursuit activates for high-threat incidents when the protection objective extends beyond immediate containment. It continues tracking subjects, vehicles, infrastructure and lawful intelligence leads until the case is resolved, handed to competent authorities or explicitly closed.

> HIGH-THREAT INCIDENT  
> ↓  
> PRESERVE SUBJECT / VEHICLE / CYBER TRACKS  
> ↓  
> CORRELATE CAMERAS + ACCESS + FIELD + OPEN INTELLIGENCE  
> ↓  
> MAINTAIN LAST VERIFIED OBSERVATION  
> ↓  
> BUILD CASEGRAPH + ATTRIBUTION LEADS  
> ↓  
> AUTHORITY HANDOFF / CONTINUED WATCH

## 15.1 Pursuit principles

- Track observations, not assumptions.

- Every association carries confidence and source provenance.

- Private or protected information enters only through lawful authority or approved contractual access.

- Sentinel does not autonomously intrude into external systems.

- High-threat pursuit maintains an updated last verified observation rather than pretending continuous certainty when coverage is lost.

# 16. Sentinel Identity

Identity is a candidate-generation and verification subsystem, not an accusation engine. Facial analysis may help associate temporary tracks with authorised watchlists or other lawfully available reference material, but the result remains a candidate until independently verified.

| **Level**                    | **Meaning**                                                     |
|------------------------------|-----------------------------------------------------------------|
| I0 UNKNOWN                   | No identity information.                                        |
| I1 POSSIBLE CANDIDATE        | Weak similarity or contextual lead.                             |
| I2 PROBABLE CANDIDATE        | Multiple observations support candidate.                        |
| I3 HIGH-CONFIDENCE CANDIDATE | Strong technical match plus corroborating evidence.             |
| I4 HUMAN VERIFIED            | Authorised human verification.                                  |
| I5 AUTHORITY VERIFIED        | Identity confirmed by competent authority or authorised source. |

Model version, image quality, threshold, demographic performance testing and known limitations must be stored with identity results. This design aligns with NIST guidance that AI systems require lifecycle measurement and risk management rather than reliance on a single accuracy number.

# 17. Sentinel Vehicle

- Vehicle detection and anonymous track IDs.

- Colour/type and make/model estimation where model quality supports it.

- Plate recognition integration with confidence and image-quality metadata.

- Entry/exit history.

- Cross-camera route reconstruction.

- Person-to-vehicle association.

- Vehicle watchlists where lawfully authorised.

- Last verified observation and predicted route options clearly distinguished.

# 18. Sentinel Access

Access events give Vision context. Sentinel should correlate credentials, schedules, visitors, doors, gates, turnstiles, QR passes and later RFID/NFC or other physical access technologies. A person crossing a restricted doorway without a corresponding access event is more meaningful than video movement alone.

# 19. Sentinel Perimeter

- Virtual and physical boundary monitoring.

- Direction and line-crossing analysis.

- Fence and perimeter sensors.

- Vehicle approach and dwell analysis.

- Thermal-camera events where available.

- After-hours movement.

- Route and escape-corridor modelling.

- Automatic association of nearby cameras and patrol resources.

# 20. Sentinel Edge

Edge is mandatory for serious deployments because critical protection cannot depend entirely on wide-area connectivity. Edge nodes connect local cameras and sensors, perform approved local analytics, buffer evidence, maintain device health, enforce critical local rules and synchronise with central services when connectivity is available.

> SITE DEVICES  
> ↓  
> SENTINEL EDGE  
> ├─ DEVICE MANAGER  
> ├─ VIDEO PIPELINE  
> ├─ LOCAL EVENT BUS  
> ├─ LOCAL POLICY CACHE  
> ├─ TEMPORARY EVIDENCE BUFFER  
> ├─ OFFLINE FIELD/COMMAND SUPPORT  
> └─ SECURE CLOUD SYNC

## 20.1 Edge security

- Device certificate and hardware identity.

- Secure boot and signed software where hardware supports it.

- Encrypted local storage.

- Restricted outbound connectivity.

- Configuration attestation.

- Automatic quarantine on integrity failure.

- Redundant Edge for critical sites.

# 21. Sentinel Mobile

The protected-user application is separate from the Field application. Its functions may include discreet distress signalling, temporary guardian journeys, incident reporting, site alerts, evacuation instructions, authorised temporary location sharing, visitor credentials, emergency contact display and safe-location guidance.

# 21A. Sentinel Guest Protection — Hospitality, Visitor and Public-Facing Protection

Sentinel Guest Protection turns the protected-user capability into a complete operational profile for environments in which many people are temporary visitors rather than trained employees. It is designed for hotels, resorts, heritage parks, tourist destinations, event venues, hospitals, schools, universities, shopping environments, gated communities, transport facilities and other sites where a visitor may need protection without becoming a full Sentinel user.

The design rule is simple: **a guest should be able to reach Sentinel quickly without being forced to install a full application, create a permanent account or understand the site's security structure.**

## 21A.1 Why Guest Protection exists

Traditional visitor protection is fragmented between reception desks, emergency telephone numbers, security posts, hotel staff, event staff and whatever messaging application happens to be available. Sentinel Guest Protection gives the site one controlled route from a visitor's need to an authorised response while preserving privacy, context, evidence and operational accountability.

It must answer:

1. Who is asking for protection, or what temporary credential/session is associated with the request?
2. Where is the guest now, within the accuracy and permission available?
3. What kind of help is being requested?
4. Does the guest need a visible, discreet or silent response?
5. Which responder or service is appropriate?
6. What site context matters, such as room, ticket, event, tour group, transport booking or dependent relationship?
7. What information can be collected lawfully and for how long?
8. How will the guest know that the request has been received without increasing risk?
9. What record should be retained after the event?

## 21A.2 Deployment environments

The same subsystem can be configured for different operational profiles:

- Hotel and resort guest protection.
- Heritage park and tourism-site visitor protection.
- Event and venue protection.
- Hospital visitor and patient-support protection.
- School and university visitor protection.
- Estate and residential guest protection.
- Corporate-campus visitor protection.
- Transport-hub or managed-journey protection.
- Temporary high-profile event or conference protection.

The product remains Sentinel. The organisation configures its own guest intents, response protocols, responder groups, data-retention rules and communication channels.

## 21A.3 Access channels

Guest Protection must support several entry paths so the visitor can use the channel appropriate to the site:

- Signed mobile-web link from a booking, ticket, invitation or visitor pass.
- QR code displayed on a ticket, room information card, venue sign, badge or access point.
- NFC tap point where the site chooses to deploy one.
- Progressive Web App shortcut for repeat visitors or longer stays.
- Sentinel Mobile for users who already have the application.
- Staff-assisted creation from Command, reception, concierge, medical desk or security post.
- Approved wearable or temporary device where the organisation provides one.
- Organisation-configured Whisper inputs such as word, sound, gesture, motion, device action or multimodal combination.

A QR or NFC entry point must resolve to a signed, short-lived or appropriately scoped session rather than exposing sensitive site information in the code itself.

## 21A.4 Guest protection identity

Sentinel Guest Protection should distinguish between **identity** and **temporary protective context**.

A visitor may be represented by:

```text
guest_session_id
visitor_pass_id
booking_or_ticket_reference
optional verified identity
host_or_group
room_or_location_context where lawful
arrival_window
departure_or_expiry
dependent_relationships
approved contact channels
consent / privacy state
```

Not every guest must be fully identified. Some sites may permit anonymous or pseudonymous protection requests while still capturing the minimum location and incident context needed to respond.

Where a hotel, ticketing platform, event system or visitor-management platform provides context, Sentinel should ingest only the fields required for the protective purpose.

## 21A.5 Guest intents

Guest-facing intents are organisation-configured and should use plain language appropriate to the environment. Typical intent families include:

- Security assistance.
- Medical assistance.
- Fire or evacuation assistance.
- Injury or accident.
- Lost or separated person.
- Child or dependant assistance.
- Harassment, coercion or unsafe situation.
- Discreet assistance.
- Transport or vehicle distress.
- Missing property where the site's security process covers it.
- Guardian journey overdue.
- Other urgent protection request.

These are **intent families**, not universal hard-coded commands. Each organisation maps them to its own approved protocols.

## 21A.6 Guest Protection flow

```text
GUEST / VISITOR
      ↓
QR / NFC / MOBILE WEB / APP / WHISPER / STAFF
      ↓
SIGNED GUEST SESSION OR TEMPORARY CONTEXT
      ↓
INTENT + LOCATION/ZONE + OPTIONAL CONTEXT
      ↓
CONSTITUTION + PRIVACY/POLICY CHECK
      ↓
INCIDENT / PROTECTION SESSION
      ↓
COMMAND
      ↓
APPROPRIATE FIELD / MEDICAL / FIRE / GUEST-SERVICE RESPONSE
      ↓
ACKNOWLEDGEMENT TO GUEST
      ↓
TIMELINE + RESOLUTION + RETENTION POLICY
```

A high-risk request may suppress visible acknowledgement on the originating device if the configured protocol specifies silent handling.

## 21A.7 Whisper for guests and hospitality staff

Guest Protection uses the same configurable Whisper engine as the rest of Sentinel. It does not introduce universal code phrases or gestures.

An organisation can define separate signal sets for:

- Guests.
- Front-desk or concierge staff.
- Housekeeping.
- Tour guides.
- Drivers.
- Medical personnel.
- Security personnel.
- Event staff.
- Executive or VIP protection teams.

Example policy structure:

```text
signal: organisation-defined phrase or gesture
authorised context: hotel reception staff on duty
valid site: property A
intent: possible coercion
response mode: SILENT
protocol: HOSP-COERCION-04
confirmation: discreet haptic acknowledgement
```

The signal definition and the protocol remain independently versioned so the organisation can rotate the signal without changing the response logic, or improve the response logic without retraining the signal.

## 21A.8 Guardian journeys

A guest, visitor or protected user can begin a temporary journey:

```text
START
current location
destination
expected arrival window
optional route or transport context
      ↓
ACTIVE GUARDIAN JOURNEY
      ↓
arrival confirmation
OR
overdue / unexpected deviation
      ↓
configured check-in
      ↓
escalation only when policy conditions are met
```

Guardian journeys should be time-bound and location collection must stop when the journey ends, expires or is cancelled unless another lawful protective condition exists.

## 21A.9 Family and dependent protection

Guest Protection should model temporary relationships such as:

- Parent and child.
- Guardian and dependant.
- Tour leader and group.
- Teacher and school group.
- Event organiser and participants.
- Host and visitor.
- Patient and accompanying person.

A lost/separated-person protocol can therefore correlate the dependent relationship, last verified location, relevant cameras and authorised field teams without exposing unrelated guest information.

## 21A.10 Hospitality response integration

A protection request does not always require a security officer. Sentinel Response should dispatch according to the intent and site policy.

Possible responder classes:

- Security team.
- Medical team.
- Fire or evacuation team.
- Guest services.
- Duty manager.
- Transport team.
- Child/dependent support team.
- Facility team.
- External authorised emergency service.

The operator sees the same incident object, but the playbook determines which team receives what information.

## 21A.11 Booking, ticketing and property-system integration

Guest Protection should use adapters rather than embed vendor-specific logic into the core.

Potential adapters:

```text
BookingAdapter
TicketingAdapter
VisitorManagementAdapter
HospitalityPmsAdapter
AccessCredentialAdapter
TransportBookingAdapter
IdentityAdapter
NotificationAdapter
```

Possible context includes booking reference, ticket/pass, host, room or accommodation reference, group, arrival/departure window and approved communication channel. The minimum necessary information should be copied into Sentinel; the rest should stay in the source system.

## 21A.12 Location and privacy

Location is collected according to context, consent, role and active protection purpose.

Recommended rules:

- Do not continuously track ordinary guests by default.
- Request precise device location only when the guest starts a protection function that requires it, or when another lawful site policy applies.
- Use site-zone context when precise coordinates are unavailable.
- Give guardian journeys explicit start and end.
- Expire temporary guest-location records aggressively unless an incident, legal hold or approved retention rule requires preservation.
- Separate operational location from historical analytics.
- Audit access to sensitive guest location.
- Never expose guest location to staff who are not authorised for the active response.

## 21A.13 No-install mobile-web experience

The first Guest Protection client should be a fast, mobile-first Progressive Web App.

Minimum screen flow:

```text
OPEN SIGNED LINK / QR
      ↓
SITE IDENTITY + TRUST INDICATOR
      ↓
PROTECTION OPTIONS
      ↓
SELECT OR USE CONFIGURED DISCREET INPUT
      ↓
LOCATION PERMISSION WHEN REQUIRED
      ↓
REQUEST SENT
      ↓
APPROPRIATE ACKNOWLEDGEMENT
      ↓
LIVE STATUS / SAFE INSTRUCTIONS WHEN POLICY PERMITS
```

The experience must remain usable on slow networks and low-cost mobile devices. Critical submission should be small, retryable and idempotent.

## 21A.14 Offline and degraded operation

Guest Protection cannot promise full service without connectivity, but it must fail intelligently.

Where possible:

- Cache the site's emergency/protection page shell.
- Display known local emergency and security contact routes when online submission is unavailable.
- Queue non-critical reports for retry.
- Allow Sentinel Edge or local network entry points to accept supported on-site requests during WAN loss.
- Show the user whether Sentinel has actually acknowledged a request.
- Never display a false success state when the request has not reached an authorised Sentinel component.

## 21A.15 Guest Protection metrics

Measure:

```text
time from guest action to accepted event
time from accepted event to Command visibility
time to responder assignment
time to guest acknowledgement
time to responder arrival where measured
percentage of requests with usable location
percentage of accidental/false activations
guest-web delivery success
QR/NFC session validation failure
privacy/retention-policy compliance
guardian-journey completion and overdue-resolution rate
```

Metrics should be separated by intent type because medical, security, fire and service responses have different operational targets.

## 21A.16 Guest Protection boundaries

Guest Protection must not become a hidden mass-tracking feature.

It should not:

- Track every hotel guest or park visitor continuously by default.
- Treat booking data as permission for unrelated surveillance.
- Expose room, identity or location information to staff without operational need.
- Make biometric identification mandatory for ordinary visitor protection.
- Create permanent profiles from temporary visits unless there is a separate lawful basis.
- Replace trained site staff, medical procedures, fire procedures or officially authorised emergency routes.

Sentinel coordinates protection. It does not manufacture operational capability where the organisation has none.

# 22. Sentinel OpenIntel and DarkWatch

## 22.1 OpenIntel

OpenIntel collects and correlates lawfully accessible public information relevant to an active protective or investigative purpose. It can work with public websites, public social-media content, published aliases, news, public business records and approved threat-intelligence feeds. It must not bypass private-account controls or fabricate certainty from weak username similarity.

## 22.2 DarkWatch

DarkWatch is a separated intelligence-collection environment for high-risk sources, including Tor-based sources where lawful and operationally justified. Sentinel itself should remain on hardened conventional/private infrastructure. DarkWatch content passes through isolation, malware/content inspection and sanitisation before structured intelligence reaches the core platform.

> HIGH-RISK SOURCE  
> ↓  
> ISOLATED COLLECTOR  
> ↓  
> MALWARE / CONTENT INSPECTION  
> ↓  
> SANITISATION  
> ↓  
> STRUCTURED INTELLIGENCE  
> ↓  
> CASEGRAPH / FUSION

# 23. Sentinel Controlled Reality

Controlled Reality is the defender-controlled environment used when a detected adversary should be contained away from real assets while their behaviour, intent and techniques are observed. It is more than a static decoy. The environment should be coherent enough that the adversary behaves naturally, while every asset and interaction remains controlled by the defender.

## 23.1 Possible controlled assets

- Controlled workstations and servers.

- Controlled administrative consoles.

- Controlled databases and file shares.

- Controlled documents and credentials.

- Controlled APIs and internal applications.

- Controlled cloud resources.

- Controlled identities and communication channels.

## 23.2 Controlled Reality levels

| **Level**                         | **Purpose**                                                                                 |
|-----------------------------------|---------------------------------------------------------------------------------------------|
| CR-0 Observation                  | Observe without altering the operational environment.                                       |
| CR-1 Instrumented Assets          | Use defender-controlled canary assets and markers.                                          |
| CR-2 Controlled Diversion         | Redirect suspicious activity away from sensitive production resources.                      |
| CR-3 Investigative Environment    | Fully instrumented environment to study objectives, tools and behaviour.                    |
| CR-4 Strategic Controlled Reality | High-authority, multi-asset environment used only under explicit policy and legal approval. |

## 23.3 Evidence requirements

Every Controlled Reality session must record why it was activated, the authorisation, assets presented, environment version, adversary interactions, files introduced, network activity, defender interventions and session closure. This makes later analysis distinguish observed adversary behaviour from defender-generated conditions.

# 24. Sentinel Cyber and Sentinel Shield

## 24.1 Cyber

Sentinel Cyber handles cyber events affecting protected organisations and Sentinel infrastructure. It ingests authentication, endpoint, network, cloud, API and security-tool telemetry, then correlates those events with physical incidents when relevant.

## 24.2 Shield

Shield protects Sentinel itself. The platform must assume that operator accounts, cameras, Edge nodes, AI models, APIs, software updates and evidence systems are valuable attacker targets.

## 24.3 Zero-trust design

NIST SP 800-207 defines zero trust around protecting resources rather than granting implicit trust based on network location. Sentinel adopts this principle: users, services and devices authenticate and receive least-privilege authorisation before accessing resources.

## 24.4 Device trust states

| **State**   | **Meaning**                                                       |
|-------------|-------------------------------------------------------------------|
| TRUSTED     | Identity and integrity checks healthy.                            |
| DEGRADED    | Operational but one or more assurance controls degraded.          |
| SUSPICIOUS  | Unexpected behaviour or integrity concern.                        |
| QUARANTINED | Communication restricted while investigation occurs.              |
| COMPROMISED | Evidence supports loss of trust; excluded from trusted decisions. |
| OFFLINE     | Unavailable or unreachable.                                       |

## 24.5 Sensor trust scoring

Fusion must consider whether a source itself might be compromised. A camera with integrity anomalies should contribute less confidence than several independently trusted sensors. This protects the system against replayed video, frozen streams, tampered timestamps and compromised devices.

## 24.6 AI integrity

- Signed and versioned model artifacts.

- Approved-model registry.

- Threshold and configuration audit trail.

- Drift monitoring.

- Unexpected inference-pattern detection.

- Training/evaluation dataset provenance.

- Rollback capability.

- Crucible testing against MITRE ATLAS-aligned AI attack families.

# 25. Sentinel Crucible and Sentinel Chimera

## 25.1 Crucible

Crucible is Sentinel’s continuous adversarial assurance system. It maps the attack surface, evaluates known adversary methods, generates scenarios, executes authorised security checks, challenges assumptions and converts every failure into a permanent regression scenario.

> KNOW THE SYSTEM  
> ↓  
> MODEL ATTACK SURFACE  
> ↓  
> KNOWN METHODS + THREAT INTELLIGENCE  
> ↓  
> CHIMERA HYPOTHESES  
> ↓  
> ATTACK GRAPH  
> ↓  
> SAFETY CLASSIFICATION  
> ↓  
> PRODUCTION-SAFE CHECK OR DIGITAL TWIN TEST  
> ↓  
> FINDING → REMEDIATION → RETEST → REGRESSION

## 25.2 Chimera

Chimera invents new adversary hypotheses. It does not need to generate exploit malware. It combines trust relationships, site topology, user roles, known weaknesses, historical attacks, MITRE ATT&CK techniques, MITRE ATLAS techniques, operational timing and human factors to ask what sequence could produce an unacceptable outcome.

## 25.3 Crucible execution levels

| **Level**                 | **Execution boundary**                                                               |
|---------------------------|--------------------------------------------------------------------------------------|
| L0 — ANALYSIS             | No execution. Architecture and attack-path reasoning only.                           |
| L1 — PASSIVE              | Configuration, inventory, dependency and telemetry inspection.                       |
| L2 — SAFE VALIDATION      | Non-destructive checks against authorised production resources.                      |
| L3 — ATTACK EMULATION     | Approved adversary behaviours in staging or Digital Twin.                            |
| L4 — ADVERSARIAL RESEARCH | Novel and potentially destructive tests in isolated laboratory environments.         |
| L5 — FULL EXERCISE        | Authorised cyber-physical exercise involving people, systems and response playbooks. |

## 25.4 Sentinel Adversary

A dedicated challenge component questions conclusions such as “attack contained”, “identity confirmed” or “site secure”. It asks what evidence proves persistence is removed, which alternate credentials may exist, what blind routes remain, which sources are degraded and which assumptions have not been tested.

# 26. Sentinel Case and Sentinel Evidence

## 26.1 Sentinel Case

Case converts raw telemetry into a structured investigative record. It separates fact, inference, intelligence lead and allegation so that weak assumptions do not gradually become apparent facts.

| **Classification** | **Meaning**                                             |
|--------------------|---------------------------------------------------------|
| FACT               | Directly supported by preserved evidence.               |
| INFERENCE          | Reasoned conclusion supported by one or more facts.     |
| INTELLIGENCE LEAD  | Potentially useful relationship requiring verification. |
| ALLEGATION         | Reported claim not independently established.           |

## 26.2 Evidence Vault

Original evidence is immutable after ingestion. Enhancements, annotations, AI analysis and clips are stored as derived objects linked to the preserved original. Each item receives provenance, time, source identity, hash, classification, retention rule, access history and export history.

## 26.3 Chain of custody

> EVIDENCE E-771  
> 14:22:18 created by CAM-17  
> 14:22:19 ingested by EDGE-03  
> 14:22:20 stored in Evidence Vault  
> 15:01:11 viewed by Investigator I-12  
> 15:08:52 derived clip created  
> 15:17:21 export approved  
> 15:18:02 transferred under authority reference

## 26.4 CaseGraph

CaseGraph links subjects, temporary tracks, vehicles, devices, accounts, aliases, infrastructure, organisations, locations, incidents, evidence and historical campaigns. Every graph edge stores source, confidence, first/last seen and verification status.

## 26.5 Attribution ladder

| **Level**                      | **Meaning**                                                                      |
|--------------------------------|----------------------------------------------------------------------------------|
| A0 UNKNOWN                     | No useful attribution.                                                           |
| A1 TECHNICAL CLUSTER           | Related infrastructure, tools or behavioural pattern.                            |
| A2 CAMPAIGN                    | Likely coordinated series of incidents.                                          |
| A3 ACTOR CLUSTER               | Evidence supports a common operating entity.                                     |
| A4 IDENTITY CANDIDATE          | Possible real-world identity requiring verification.                             |
| A5 HIGH-CONFIDENCE ATTRIBUTION | Multiple independent sources support attribution.                                |
| A6 AUTHORITY VERIFIED          | Identity confirmed through competent investigative authority.                    |
| A7 OFFICIAL LEGAL STATUS       | Recorded only from official legal process; Sentinel does not invent this status. |

## 26.6 Authority handoff package

- Executive case summary.

- Incident classification and chronology.

- Subject and vehicle tracks.

- Candidate identities with confidence and verification status.

- Technical infrastructure and public-source leads.

- Physical and digital evidence manifest.

- Controlled Reality records.

- Field and sensor reports.

- Attribution assessment and alternative hypotheses.

- Chain of custody and integrity verification.

- Outstanding investigative gaps.

- System/model versions necessary to explain technical records.

# 27. Sentinel Knowledge Graph and Campaign Memory

The broader Sentinel Knowledge Graph extends beyond a single case. It connects incidents, attack techniques, locations, vehicles, infrastructure, aliases, device failures, vulnerabilities, organisations and campaigns. New events are continuously compared against historical patterns to identify returning adversaries or repeated attack preparation.

## 27.1 Campaign object

> CAMPAIGN-017  
> First seen: ...  
> Last seen: ...  
> Linked incidents: ...  
> Targets: executive identity, finance, surveillance administration  
> Observed objectives: persistence, reconnaissance, data access  
> Known techniques: ...  
> Current status: WATCHING FOR RETURN

# 28. Sentinel Mission Assurance

Mission Assurance answers a more useful question than “is Sentinel online?” It calculates whether each protective mission remains achievable based on current device, network, personnel and service health.

| **Mission**              | **Example state**                                            |
|--------------------------|--------------------------------------------------------------|
| Main entrance protection | FULL                                                         |
| Vault observation        | DEGRADED — one camera unavailable, secondary coverage active |
| Vehicle pursuit          | PARTIAL — external camera connector unavailable              |
| Field communications     | PRIMARY DEGRADED — secondary channel active                  |
| Evidence preservation    | FULL                                                         |
| Identity verification    | LIMITED — reference service unavailable                      |

# 29. Sentinel Black Box

Black Box is an independently protected operational recorder for critical decisions and system events. It should be difficult for ordinary administrators to erase or rewrite retrospectively. Records include critical policy changes, model changes, clock status, security events, Command actions, high-consequence approvals, evidence-integrity events and mission-assurance transitions.

**PART III — ADVERSARIAL PREPAREDNESS & SCENARIO PLAYBOOKS**

How Sentinel prepares for known, combined and not-yet-observed attacks.

# 30. Scenario Playbook System

Sentinel cannot maintain a finite list of “all attacks”. Instead it maintains broad attack families, detailed scenario playbooks and a generation engine that creates variants and combinations. Every serious real incident becomes a permanent scenario and is mutated into harder future tests.

## 30.1 Playbook schema

> SCENARIO ID / NAME  
> THREAT CLASS  
> THREAT ACTOR TYPE  
> LIKELY OBJECTIVE  
> TARGETS  
> PRECONDITIONS  
> ATTACK PHASES  
> EXPECTED SIGNALS  
> EXPECTED BLIND SPOTS  
> SENTINEL DETECTIONS  
> FUSION CORRELATIONS  
> THREAT-STATE TRANSITIONS  
> CONTROLLED REALITY OPTIONS  
> COMMAND ACTIONS  
> FIELD ACTIONS  
> PURSUIT ACTIONS  
> EVIDENCE REQUIREMENTS  
> AUTHORITY HANDOFF  
> RECOVERY  
> HARDENING  
> PERFORMANCE TARGETS  
> TEST VARIANTS  
> KNOWN FAILURE MODES

# 31. Master Scenario Families

| **Scenario family**                  | **Examples**                                                                                               |
|--------------------------------------|------------------------------------------------------------------------------------------------------------|
| Physical violence and armed attack   | Robbery, armed intrusion, assault, hostage, coordinated violent entry.                                     |
| Abduction and coercion               | Forced movement of protected person, vehicle extraction, operative coercion.                               |
| Perimeter and facility intrusion     | Fence breach, restricted-zone entry, tailgating, covert entry.                                             |
| Vehicle-enabled operations           | Reconnaissance, escape vehicle, stolen vehicle identity, route manipulation.                               |
| Insider threat                       | Malicious, compromised, bribed or coerced employee/contractor.                                             |
| Cyber intrusion                      | Credential access, persistence, privilege escalation, lateral movement, collection, exfiltration, impact.  |
| Cyber-physical blended attack        | Cyber impairment used to enable physical action or physical access used to compromise cyber systems.       |
| Surveillance attack                  | Camera obstruction, replay, feed substitution, timestamp manipulation, PTZ abuse, NVR compromise.          |
| AI attack                            | Model replacement, poisoning, evasion, prompt/tool manipulation, retrieval poisoning, threshold tampering. |
| Identity attack                      | Biometric spoofing, stolen credential, impersonation, deepfake/voice replay, identity-data poisoning.      |
| Communications attack                | Jamming, message replay, forged command, compromised field device, forced insecure fallback.               |
| Supply-chain attack                  | Malicious update, dependency compromise, firmware tampering, contractor compromise.                        |
| Evidence attack                      | Deletion, alteration, timestamp attack, chain-of-custody manipulation, audit-log attack.                   |
| Controlled Reality counter-detection | Adversary recognises or attempts to escape the controlled environment.                                     |
| Availability attack                  | Power, network, cloud, Edge, storage, event-bus or database disruption.                                    |
| Diversion and overload               | False alarms, simultaneous incidents, alert fatigue, response misdirection.                                |
| Open-intelligence manipulation       | Fabricated public information, impersonation, planted indicators, false relationship graph.                |
| DarkWatch contamination              | Malicious files/content attempting to cross the intelligence isolation boundary.                           |
| Return campaign                      | Known adversary reappears with changed infrastructure or tactics.                                          |
| Unknown composite attack             | Chimera-generated chain combining technical, human, physical and timing weaknesses.                        |

# 32. Detailed Scenario Playbooks

## 32.1 Coordinated Armed Robbery

Objective: seize assets while reducing response capability. A mature scenario should include pre-attack reconnaissance, possible credential compromise, surveillance impairment, diversion, armed entry, vehicle extraction and evidence attack.

### Expected signals

- Possible reconnaissance or unusual dwell before incident.

- Abnormal privileged login or camera-configuration event.

- Restricted-zone crossing.

- Threat-like object event.

- Violence or coercion indicators.

- Access anomalies.

- Vehicle positioned or moving abnormally.

### Core Sentinel response

- Preserve pre-event and incident footage.

- Raise relevant camera priority.

- Silent high-threat response under policy.

- Discreet field coordination.

- Track subjects and vehicle.

- Open Case and Evidence objects.

- Prepare authorised external escalation package.

## 32.2 Abduction / Kidnapping

Objective: forcibly remove a protected person. Sentinel should correlate violent interaction, protected-person identity, movement into a vehicle, vehicle route and field signals.

### Expected signals

- Violent interaction or dragging pattern.

- Protected person rapidly moved toward vehicle.

- Whisper or distress intent from user/operative.

- Vehicle leaves unexpectedly.

- Camera continuity between zones.

### Core Sentinel response

- Create critical incident.

- Preserve subject and vehicle tracks.

- Maintain last verified observation.

- Coordinate discreet field response.

- Extend pursuit through authorised camera networks.

- Build authority package with time, route, vehicle and identity candidates.

## 32.3 Hostage / Coercion

Objective: maintain control over people while preventing alarm. Sentinel must understand silence as an operational requirement and avoid actions that reveal detection.

### Expected signals

- Whisper duress signal.

- Unusual posture or movement pattern.

- Access activity inconsistent with normal workflow.

- Field operative compromised state.

### Core Sentinel response

- Set SILENT response.

- Limit notifications to authorised roles.

- Prioritise camera observation.

- Prevent visible originating-device acknowledgement.

- Stage response based on approved playbook and authority.

## 32.4 Insider-Assisted Intrusion

Objective: use legitimate access, knowledge or credentials to bypass external defences.

### Expected signals

- Valid credential used outside expected pattern.

- Off-duty access.

- Repeated security-device interaction.

- Restricted information access followed by physical anomaly.

### Core Sentinel response

- Avoid treating valid credential as automatic trust.

- Correlate schedule, behaviour, field and camera context.

- Preserve access history.

- Apply two-person controls to sensitive administrative action.

## 32.5 Surveillance Impairment Before Physical Attack

Objective: reduce visibility while a separate team acts physically.

### Expected signals

- Camera configuration change.

- Stream freeze or obstruction.

- PTZ movement away from protective mission.

- Edge or NVR admin anomaly.

- Physical movement begins soon after.

### Core Sentinel response

- Shield evaluates device trust.

- Mission Assurance identifies coverage loss.

- Adjacent cameras compensate.

- Fusion evaluates cyber-physical relationship.

- Crucible regression created after incident.

## 32.6 Credential Takeover and Persistent Cyber Intrusion

Objective: gain continuing access and information rather than immediate damage.

### Expected signals

- Abnormal authentication.

- Privilege discovery.

- Lateral movement.

- Persistent access attempt.

- Data collection.

### Core Sentinel response

- Preserve evidence before containment.

- Hunt for persistence across environment.

- Open Adversary Case.

- Controlled Reality may be used on defender-owned infrastructure under policy.

- Build behavioural fingerprint and watch for return.

## 32.7 Evidence-Integrity Attack

Objective: undermine later ability to prove what happened.

### Expected signals

- Clock manipulation.

- Evidence deletion attempt.

- Audit-log anomaly.

- Model/configuration change during incident.

### Core Sentinel response

- Black Box independently records changes.

- Evidence originals remain immutable.

- Affected source trust downgraded.

- Case explicitly distinguishes verified from compromised records.

## 32.8 Communication Spoofing Against Field Teams

Objective: send false instructions or disrupt Command-to-field trust.

### Expected signals

- Unexpected device identity.

- Message replay.

- Unusual command pattern.

- Field acknowledgement mismatch.

### Core Sentinel response

- Strong device/user identity.

- Message freshness and authenticated group state.

- Quarantine suspicious device.

- Secondary trusted channel used if required.

## 32.9 AI Model Manipulation

Objective: alter Sentinel perception or decision quality.

### Expected signals

- Model hash mismatch.

- Unapproved model version.

- Unexpected threshold change.

- Abnormal inference distribution.

### Core Sentinel response

- Stop trusting affected model.

- Rollback to approved version.

- Fusion reduces affected-source confidence.

- Crucible reproduces manipulation in lab.

- Supply-chain investigation opened.

## 32.10 Multi-Site Coordinated Diversion

Objective: overload central Command or move responders away from the true target.

### Expected signals

- Multiple low/medium alerts across sites.

- One site shows correlated higher-value indicators.

- Abnormal timing similarity.

### Core Sentinel response

- Campaign-level correlation.

- Mission Assurance protects minimum coverage at every site.

- Response cannot drain all resources from high-value missions.

- Command receives coordinated-operation hypothesis.

## 32.11 Controlled Reality Counter-Detection

Objective: adversary tests whether presented systems are controlled and attempts escape or manipulation.

### Expected signals

- Unusual environment fingerprinting.

- Attempts to discover routing boundaries.

- Adversary deliberately generates misleading behaviour.

### Core Sentinel response

- Keep controlled environment isolated.

- Record all environment changes and analyst actions.

- Never permit pivot to production.

- Case marks observations that may be adversary-generated misinformation.

## 32.12 Known Adversary Return

Objective: re-enter with changed infrastructure after previous attack.

### Expected signals

- New IP/domain but repeated target selection, timing, tools or behaviour.

- Historical campaign similarity.

### Core Sentinel response

- Compare against Campaign Memory.

- Open possible-return hypothesis.

- Increase relevant telemetry retention and analysis.

- Do not declare identity solely from behavioural similarity.

## 32.13 Hospitality and Visitor Protection Scenarios

Guest Protection scenarios are handled through the same incident, Fusion, Whisper, Command, Field, Evidence and playbook architecture as other Sentinel operations. The difference is the temporary identity/context model and the privacy constraints of public-facing environments.

| **Scenario** | **Primary signals/context** | **Core Sentinel handling** |
|---|---|---|
| Guest medical emergency | Guest request, staff report, fall indicator, room/zone context, optional health information voluntarily supplied for the active event. | Create medical incident, identify site medical response, surface safe route/location, notify Command as policy requires, preserve only relevant information. |
| Lost or separated child/dependant | Guardian request, dependant relationship, last verified location, ticket/group context, relevant camera tracks where authorised. | Protect the dependant case, restrict identity visibility, search authorised site observations, coordinate designated staff, maintain guardian communication and closure confirmation. |
| Harassment, coercion or unsafe situation | Guest request, configured Whisper signal, staff observation, camera context, location. | Use discreet or silent response where configured, minimise visible acknowledgement, notify authorised personnel, preserve relevant evidence, separate guest safety from investigative identity conclusions. |
| Fire or evacuation | Fire/smoke event, site alarm, guest location/zone where available, facility state. | Deliver approved evacuation guidance, direct guests toward safe/assembly areas, coordinate field/fire roles, avoid routing through unsafe zones. |
| Guardian journey overdue | Journey timer, destination, check-in state, last authorised location. | Request safe confirmation, assess connectivity/context, escalate according to organisation policy, stop tracking after resolution. |
| Transport or vehicle distress | Guest journey/transport context, driver or vehicle reference, location, guest report. | Create appropriate security/medical/transport response, correlate authorised vehicle information and maintain guest communication. |
| Hospitality staff covert request | Organisation-configured Whisper signal, staff identity, duty state, location and signal confidence. | Apply anti-spoofing/context checks, invoke configured protocol, use silent/discreet acknowledgement and bring nearby cameras or field units into the incident only as authorised. |

Each organisation must test these playbooks through drills and Crucible scenarios before calling the hospitality deployment Sentinel Ready.

# 33. Sentinel Attack Graph

Crucible maintains attack graphs describing possible paths from an adversary starting condition to a protected objective. Each edge stores required capability, credential, trust assumption, existing control, detection coverage and potential impact. Cyber and physical paths are allowed to meet at the same protected asset.

> CYBER PATH PHYSICAL PATH  
> Contractor credential Visitor credential  
> ↓ ↓  
> Camera administration Restricted corridor  
> ↓ ↓  
> Coverage degradation + Insider-opened door  
> \\ /  
> \\ /  
> PROTECTED TARGET

# 34. Sentinel Digital Twin

Digital Twin is the safe environment where Chimera hypotheses and potentially destructive tests are validated. It models networks, services, identities, roles, cameras using simulated feeds, sensors, access control, Edge nodes, databases with synthetic data, Command, Field and response playbooks.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Controlled Reality vs Digital Twin</strong><br />
Controlled Reality involves a real detected adversary inside a defender-controlled environment. Digital Twin involves simulated or authorised test adversaries inside a defender-controlled test environment. They share tooling but serve different purposes.</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

**PART IV — ENGINEERING & BUILD ARCHITECTURE**

How the platform should be implemented, secured, tested and evolved.

# 35. Build Strategy

The first implementation should avoid premature microservice sprawl. Start with a modular core platform whose domain boundaries are explicit, plus separate services for workloads that genuinely require independent scaling or isolation: realtime communications, video/AI processing, Edge runtime, evidence processing and selected intelligence collectors.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Recommended structural rule</strong><br />
Modular monolith for business domains + separate realtime/vision/Edge workloads. Extract additional services only when scaling, security isolation or independent deployment clearly requires it.</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

# 36. Recommended Technology Stack

| **Layer**                      | **Recommended baseline**                                     | **Reason**                                                                                    |
|--------------------------------|--------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| Command/Admin Web              | React + TypeScript                                           | Mature component ecosystem, complex realtime UI, strong typing.                               |
| Core Backend                   | TypeScript + NestJS                                          | Structured modules, strong contracts, fast product development.                               |
| Performance-sensitive services | Go or Rust as required                                       | Suitable for high-concurrency gateways, device services or hardened agents when justified.    |
| Primary database               | PostgreSQL + PostGIS                                         | Transactional system of record plus spatial queries for zones, routes and nearest responders. |
| Event transport                | NATS JetStream-class messaging                               | Lightweight event distribution and durable streams for the initial architecture.              |
| Cache/presence                 | Redis-compatible store                                       | Presence, ephemeral state, throttling, fast lookup.                                           |
| Evidence/object storage        | S3-compatible immutable-capable object storage               | Large video/evidence objects separated from transactional database.                           |
| Search/analytics               | OpenSearch/ClickHouse class tools when scale requires        | Fast event, log and analytical query workloads.                                               |
| Graph intelligence             | PostgreSQL first; dedicated graph engine later if required   | Avoid an extra database until CaseGraph complexity justifies it.                              |
| Vision runtime                 | NVIDIA DeepStream/TensorRT candidate + ONNX portability      | High-throughput multi-stream edge analytics with a path to model portability.                 |
| Mobile                         | Flutter candidate                                            | Separate Field and protected-user apps from one strongly controlled codebase.                 |
| Edge OS                        | Hardened Linux + containers                                  | Portable deployment, device integration and update control.                                   |
| Observability                  | OpenTelemetry + Prometheus-compatible metrics + central logs | Unified metrics, traces and logs.                                                             |

# 37. Monorepo Structure

> sentinel/  
> ├─ apps/  
> │ ├─ command-web/  
> │ ├─ admin-web/  
> │ ├─ field-mobile/  
> │ ├─ protected-mobile/  
> │ └─ edge-console/  
> ├─ services/  
> │ ├─ core-api/  
> │ ├─ realtime/  
> │ ├─ fusion/  
> │ ├─ vision-control/  
> │ ├─ notifications/  
> │ ├─ intelligence/  
> │ └─ integrations/  
> ├─ edge/  
> │ ├─ gateway/  
> │ ├─ video-pipeline/  
> │ ├─ device-manager/  
> │ └─ offline-runtime/  
> ├─ packages/  
> │ ├─ contracts/  
> │ ├─ auth/  
> │ ├─ permissions/  
> │ ├─ events/  
> │ ├─ policy/  
> │ ├─ incidents/  
> │ ├─ geo/  
> │ ├─ evidence/  
> │ ├─ observability/  
> │ └─ ui/  
> ├─ ai/  
> │ ├─ models/  
> │ ├─ evaluation/  
> │ ├─ datasets/  
> │ ├─ experiments/  
> │ └─ calibration/  
> ├─ infrastructure/  
> │ ├─ containers/  
> │ ├─ kubernetes/  
> │ ├─ terraform/  
> │ ├─ pki/  
> │ └─ monitoring/  
> ├─ docs/  
> │ ├─ architecture/  
> │ ├─ threat-models/  
> │ ├─ playbooks/  
> │ ├─ privacy/  
> │ └─ operations/  
> └─ tests/  
> ├─ integration/  
> ├─ simulation/  
> ├─ performance/  
> ├─ security/  
> └─ acceptance/

# 38. Core Service Boundaries

| **Service/domain**      | **Responsibilities**                                                                        |
|-------------------------|---------------------------------------------------------------------------------------------|
| Identity & Organisation | Users, organisations, sites, roles, shifts, clearance, device association.                  |
| Site & Asset            | Digital twin, zones, devices, cameras, sensors, access points, missions.                    |
| Event                   | Normalised event ingestion, validation, deduplication, schema versioning.                   |
| Fusion                  | Correlation, hypotheses, threat state, confidence, contradictory evidence.                  |
| Incident                | Incident lifecycle, severity, command structure, timeline.                                  |
| Response                | Playbooks, approvals, tasks, escalation, external connectors.                               |
| Field                   | Operatives, presence, patrols, assignments, observation sessions.                           |
| Guest Protection        | Temporary visitor sessions, visitor passes, guardian journeys, guest intents, dependants, privacy-scoped location and hospitality integrations. |
| Whisper                 | Signal definitions, recognition results, context checks, intent output.                     |
| Case                    | CaseGraph, attribution ladder, hypotheses, authority package.                               |
| Evidence                | Immutable object references, hashes, custody, derived evidence, export.                     |
| Policy/Constitution     | Hard constraints, approval requirements, policy versioning and signed decision enforcement. |
| Mission Assurance       | Dependency graph and protection-objective health.                                           |
| Crucible                | Scenario library, attack graphs, test scheduling, findings and regression.                  |

# 39. Data Architecture

## 39.1 Primary entity groups

- Organisations, sites, buildings, floors, zones and routes.

- Users, roles, clearances, teams, shifts and devices.

- Cameras, sensors, Edge nodes, access points and device trust state.

- Events, correlations, hypotheses and incidents.

- Field operatives, patrols, checkpoints and observation sessions.

- Guest sessions, visitor passes, booking/ticket context links, guardian journeys, dependants, guest intents, temporary consent and privacy-scoped location records.

- Temporary person/vehicle tracks and candidate identities.

- Cases, campaigns, graph relationships and attribution records.

- Evidence, hashes, custody, exports and retention.

- Playbooks, policies, approvals and Constitution versions.

- Models, evaluations, deployments and performance metrics.

- Mission objectives, dependencies and assurance state.

- Crucible scenarios, attack graphs, tests, findings and regressions.

## 39.2 Multi-tenancy

Tenant boundaries must be enforced in every record and service. Cross-organisation access is denied by default and permitted only through explicit platform authority. Evidence, identity and intelligence objects require stronger isolation than ordinary configuration data.

# 40. Normalised Event Contract

> {  
> "event_id": "evt\_...",  
> "schema_version": 1,  
> "organisation_id": "...",  
> "site_id": "...",  
> "zone_id": "...",  
> "source_type": "camera\|access\|field\|sensor\|cyber\|intel",  
> "source_id": "...",  
> "source_trust": "trusted\|degraded\|suspicious\|quarantined",  
> "event_type": "...",  
> "confidence": 0.91,  
> "occurred_at": "...",  
> "ingested_at": "...",  
> "location": {},  
> "track_ids": \[\],  
> "evidence_refs": \[\],  
> "metadata": {},  
> "trace_id": "..."  
> }

Events should be append-only. Corrections or retractions are new records that reference the earlier event rather than rewriting history.

# 41. APIs and Realtime Channels

## 41.1 API families

> /api/v1/organisations  
> /api/v1/sites  
> /api/v1/devices  
> /api/v1/events  
> /api/v1/incidents  
> /api/v1/responders  
> /api/v1/guest-sessions  
> /api/v1/visitor-passes  
> /api/v1/guardian-journeys  
> /api/v1/guest-intents  
> /api/v1/patrols  
> /api/v1/cases  
> /api/v1/evidence  
> /api/v1/playbooks  
> /api/v1/whisper  
> /api/v1/mission-assurance  
> /api/v1/crucible

## 41.2 Realtime

Realtime channels carry presence, incident changes, field acknowledgements, mission-health transitions and Command updates. High-volume video should not travel through the same general event channel. Video transport uses purpose-built streaming paths while metadata enters the event architecture.

# 42. Video and Edge Engineering

## 42.1 Device discovery and adapter model

> CameraAdapter  
> discover()  
> connect()  
> capabilities()  
> health()  
> stream()  
> events()  
> snapshot()  
> ptz()  
> recording()  
> disconnect()  
>   
> Implementations:  
> OnvifCameraAdapter  
> RtspCameraAdapter  
> VendorSpecificAdapter

## 42.2 ONVIF direction

Prefer Profile T-capable video devices for advanced streaming and Profile M for analytics metadata/events. ONVIF explicitly treats profiles as interoperability contracts; official product conformance should be checked in the ONVIF conformant-product registry rather than inferred from marketing claims.

## 42.3 Edge buffering

- Recent event metadata.

- Recent incident-relevant video window.

- Pending evidence uploads.

- Offline field messages.

- Policy cache with expiry.

- Local device-health history.

- Synchronisation queue with ordering and idempotency.

# 43. AI/ML Engineering Lifecycle

Sentinel AI follows a governed lifecycle aligned with the risk-management principles of NIST AI RMF. Models are registered, evaluated, calibrated per site, monitored after deployment and removable without taking the entire platform offline.

> RESEARCH → DATA REVIEW → TRAIN/EVALUATE → SECURITY TEST → SITE CALIBRATION → LIMITED PILOT → APPROVAL → PRODUCTION → MONITOR → RETRAIN/ROLLBACK

## 43.1 Model registry fields

- Model ID and version.

- Purpose and allowed decisions.

- Training/evaluation provenance declaration.

- Input requirements.

- Approved sites and camera classes.

- Thresholds.

- Known limitations.

- Performance by relevant subgroups and conditions.

- Security evaluation.

- Deployment date and authority.

- Rollback version.

## 43.2 Required metrics

- Precision and recall.

- False-negative and false-positive rates.

- False alarms per 100 camera-hours.

- Per-class confusion matrix.

- Detection latency P50/P95/P99.

- Tracking continuity and ID-switch rate.

- Cross-camera association accuracy.

- Performance by lighting, camera angle, resolution and site context.

# 44. Whisper Engineering

## 44.1 Architecture

> SIGNAL SOURCES  
> voice \| sound \| gesture \| motion \| device \| wearable \| context  
> ↓  
> SIGNAL NORMALISATION  
> ↓  
> MODALITY RECOGNISERS  
> ↓  
> INTENT CORRELATION  
> ↓  
> ANTI-SPOOF + CONTEXT + TRUST  
> ↓  
> CONFIDENCE  
> ↓  
> CONSTITUTION  
> ↓  
> PROTOCOL ORCHESTRATOR

## 44.2 Signal schema

> signal_id  
> organisation_id  
> name  
> classification  
> allowed_roles  
> allowed_sites/zones  
> modalities  
> combination_expression  
> recognition_thresholds  
> anti_spoof_requirements  
> valid_time/context  
> intent  
> response_mode  
> protocol_id  
> confirmation_method  
> version  
> status  
> created_by / approved_by

## 44.3 Protocol separation

Recognition produces an intent. The Response subsystem maps that intent to an independently versioned protocol. This allows organisations to improve response procedures without retraining the signal, and to rotate signals without rewriting playbooks.

# 44A. Guest Protection Engineering

Guest Protection should be implemented as a first-class domain inside the initial modular core rather than as a collection of special-case endpoints in the public website.

## 44A.1 Client architecture

Recommended clients:

```text
apps/guest-web/        mobile-first PWA / no-install access
apps/mobile/           full protected-user app
apps/command-web/      operator handling
apps/field-mobile/     responder handling
```

`guest-web` should be intentionally small. It does not receive privileged site data. It receives only the organisation branding, approved protection intents, required privacy/consent information, session context and the minimum status information authorised for that visitor.

## 44A.2 Backend domain

Initial implementation can live inside `services/core-api` as a strongly separated module:

```text
guest-protection/
├─ guest-session
├─ visitor-pass
├─ guardian-journey
├─ guest-intent
├─ dependant-link
├─ guest-location
├─ guest-consent
├─ hospitality-adapters
└─ guest-protection-policy
```

Extract it into an independent service only when scale, isolation or deployment requirements justify the operational cost.

## 44A.3 Primary data objects

```text
guest_sessions
visitor_passes
guest_context_links
guest_consents
guest_devices
guest_intent_requests
guardian_journeys
guardian_journey_updates
dependant_links
guest_location_snapshots
guest_notifications
hospitality_integration_links
```

Every temporary object requires an expiry or retention state. A guest session that has no continuing operational or legal purpose must not quietly become permanent account data.

## 44A.4 Guest session security

A guest session should use a high-entropy opaque identifier and a signed/verified server-side context.

Recommended controls:

- Short-lived activation tokens for QR/deep-link entry.
- One-time exchange of external booking/ticket tokens for a Sentinel guest session.
- Server-side validation of site, expiry and allowed functions.
- Device-bound or session-bound refresh where practical.
- Rate limiting and replay detection.
- No sensitive identity, room or incident information embedded directly in the QR payload.
- Fast session revocation.
- Separate privilege model from authenticated employee accounts.
- No access to Command, camera feeds, Case or unrelated site data.

## 44A.5 Integration flow

```text
BOOKING / TICKET / VISITOR SYSTEM
          ↓
       ADAPTER
          ↓
MINIMUM PROTECTIVE CONTEXT
          ↓
SENTINEL GUEST SESSION
          ↓
SIGNED LINK / QR / NFC
          ↓
GUEST-WEB OR MOBILE
          ↓
INTENT / JOURNEY / REPORT
```

Adapters should use stable external references rather than copying complete third-party records into Sentinel.

## 44A.6 Intent submission contract

A guest request should enter the Event service through an idempotent contract containing only the required fields:

```text
request_id
guest_session_id
site_id
intent_id
response_mode_hint
occurred_at
device_time
location_if_authorised
location_accuracy
zone_hint
context_refs
whisper_recognition_ref_if_any
consent_state
client_connectivity
```

The core converts the request into normalised events. Fusion, Constitution and Response then decide whether an incident/protection session is created and what protocol may execute.

## 44A.7 Location implementation

Use a layered location model:

1. Device GPS/geolocation when the visitor grants permission and the active function requires it.
2. Site-zone derived from signed QR/NFC location context.
3. Known ticket/room/group context where policy permits.
4. Operator/staff-confirmed location.
5. Camera-derived location only when authorised and justified by the active incident.

Each location record stores source, accuracy, confidence, collection purpose and expiry/retention state.

## 44A.8 QR and NFC architecture

A physical site point should map to a `guest_entry_point` record:

```text
entry_point_id
site_id
zone_id
type
public_label
allowed_intents
token_policy
active_from / active_until
status
```

The printed QR/NFC value should resolve through a controlled redirect/exchange endpoint. Rotatable or periodically refreshed codes are preferable for higher-risk locations.

## 44A.9 Hospitality adapter boundary

Create an adapter interface:

```text
GuestContextAdapter
resolveExternalReference()
getMinimalProtectiveContext()
validateActiveStayOrVisit()
getApprovedContactChannel()
revokeContext()
health()
```

Implementations may include ticketing, property-management, visitor-management or event systems. The core must remain functional when an external adapter is unavailable; unavailable context should degrade gracefully rather than block a genuine protection request.

## 44A.10 Whisper integration

Guest Protection consumes Whisper intents through the same signed recognition-result contract used elsewhere.

It must not duplicate recognition logic.

```text
WHISPER RECOGNISER
      ↓
SIGNED RECOGNITION RESULT
      ↓
GUEST PROTECTION CONTEXT
      ↓
CONSTITUTION / ANTI-SPOOF / POLICY
      ↓
PROTOCOL
```

Organisation-specific guest signal packs are versioned, tested and scoped by site, role/context and activation period.

## 44A.11 Realtime and notification behaviour

Guest-web receives only a scoped realtime channel for its own active session.

Permitted updates can include:

- Request accepted.
- Responder assigned, when disclosure is safe.
- Safe instruction.
- Check-in request.
- Incident resolved.
- Session expired.

Silent protocols may deliberately suppress or alter visible updates. The server, not the client, decides what acknowledgement is safe for the configured response mode.

## 44A.12 Data retention

Recommended state machine:

```text
ACTIVE
↓
RESOLVED
↓
SHORT RETENTION
↓
EXPIRED / DELETED

or

ACTIVE
↓
INCIDENT / LEGAL HOLD
↓
EVIDENCE RETENTION POLICY
```

The original booking or ticket platform remains the system of record for hospitality transactions. Sentinel retains only what its protective, audit or legal obligations require.

## 44A.13 Guest Protection testing

Required tests include:

- Expired and replayed QR/session tokens.
- Lost network during submission.
- Duplicate submissions and retries.
- Guest denies location permission.
- Incorrect zone context.
- External booking/PMS adapter unavailable.
- Silent response acknowledgement suppression.
- Accidental Whisper activation.
- Whisper spoof attempt.
- Lost/separated dependant flow.
- Guardian journey expiry and recovery.
- Privacy-role violation attempts.
- Visitor session after checkout/visit expiry.
- Command and Field response drill.
- Edge/WAN degraded operation.
- Data-expiry and legal-hold behaviour.

## 44A.14 Acceptance gate

Guest Protection is production-ready only when:

```text
NO-INSTALL ENTRY WORKS
+
REQUEST DELIVERY IS VERIFIED
+
LOCATION DEGRADES SAFELY
+
WHISPER IS CONFIGURABLE
+
COMMAND RECEIVES CORRECT CONTEXT
+
FIELD RESPONSE WORKS
+
NO UNAUTHORISED GUEST DATA IS EXPOSED
+
RETENTION/EXPIRY WORKS
+
FAILURE STATES ARE HONEST
+
SITE DRILLS PASS
```

# 45. Communications Security

Whisper and field communications should use strong authenticated encryption. For advanced group communications, the IETF Messaging Layer Security protocol is a strong design reference because it provides efficient asynchronous group key establishment with forward secrecy and post-compromise security. Sentinel still requires its own identity, device attestation, authorisation, message freshness and operational semantics around the cryptographic group layer.

# 46. Security Engineering

## 46.1 Secure-by-design baseline

Sentinel should follow NIST Secure Software Development Framework practices and treat security as part of architecture, development, release and maintenance rather than a separate penetration test near launch.

## 46.2 Core controls

- Phishing-resistant MFA for privileged users where practical.

- Passkeys/hardware security keys for Command and administration.

- Short-lived tokens and least privilege.

- Private PKI and device certificates.

- Service-to-service authentication and mTLS for sensitive internal paths.

- Network segmentation and restricted east-west access.

- Central secrets manager.

- Signed builds, containers, models and Edge releases.

- Dependency and SBOM tracking.

- Static, dynamic and container scanning.

- Rate limiting and abuse controls.

- Immutable or append-only audit trails.

- Backup restoration tests.

- Secure recovery credentials separated from ordinary Command credentials.

## 46.3 Supply-chain integrity

Every released artifact should be attributable to a controlled build pipeline. The platform should record source commit, build identity, dependency manifest, signatures and release approval. Edge software and AI models require the same treatment as backend code.

# 47. Data Governance, Privacy and Legal Controls

Sentinel handles high-risk personal data including identity, location, movement patterns and potentially biometric information. For Nigerian deployments, the Nigeria Data Protection Act 2023 and NDPC guidance require fair, lawful and accountable processing and emphasise data security, purpose limitation, minimisation and data-subject rights. Exact legal bases and retention rules must be configured with qualified counsel for each deployment.

| **Data class** | **Examples**                                                                      | **Default handling**                                             |
|----------------|-----------------------------------------------------------------------------------|------------------------------------------------------------------|
| PUBLIC         | Published organisation information                                                | Normal controlled access.                                        |
| INTERNAL       | Configuration and routine operational data                                        | Organisation access controls.                                    |
| SENSITIVE      | Field location, incident details, private contact information                     | Need-to-know, strong logging.                                    |
| RESTRICTED     | Biometric references, high-threat intelligence, privileged security configuration | Strong clearance, explicit purpose, limited retention.           |
| EVIDENCE       | Preserved incident material and chain-of-custody records                          | Immutable original, export controls.                             |
| SECRETS        | Keys, credentials, signing material                                               | Dedicated secret/key management, never ordinary database fields. |

## 47.1 Authority classification

> PUBLIC SOURCE  
> USER CONSENT  
> CONTRACTUAL SECURITY AUTHORITY  
> ORGANISATIONAL SECURITY AUTHORITY  
> LEGAL PROCESS REQUIRED  
> LAW-ENFORCEMENT / COMPETENT AUTHORITY ONLY  
> PROHIBITED

Every intelligence connector and data source should declare the authority under which its data can be used. Fusion must not treat availability as permission.

# 48. Evidence and Forensic Readiness Engineering

NIST SP 800-86 frames forensic work around identification/acquisition/protection, processing, analysis and reporting. Sentinel should implement those principles directly in evidence workflows, while recognising that jurisdiction-specific admissibility requirements require legal review.

- Synchronised clocks and clock-health monitoring.

- Source and device identity on every record.

- Cryptographic hash for evidence objects.

- Immutable originals and separate derived material.

- Chain-of-custody events.

- Export manifests and reproducible packages.

- System-health evidence showing whether the producing component was functioning normally.

- Model and configuration versions tied to AI-derived analysis.

# 49. Observability and Mission Telemetry

All core services emit structured logs, metrics, traces, health checks, security events and business events. OpenTelemetry should be the default instrumentation model so individual services do not create incompatible telemetry formats.

## 49.1 Operational health

- Camera and sensor uptime.

- Edge status and integrity.

- Event-bus lag.

- Database and object-storage health.

- Notification delivery.

- Field-device presence.

- Realtime connection health.

- Model/inference health.

- Clock synchronisation.

- Evidence backlog.

# 50. CI/CD and Environment Model

## 50.1 Environments

> LOCAL DEVELOPMENT  
> ↓  
> CI / SECURITY CHECKS  
> ↓  
> INTEGRATION  
> ↓  
> DIGITAL TWIN / STAGING  
> ↓  
> SITE PILOT  
> ↓  
> PRODUCTION

## 50.2 Production-release gates

- Code review and protected branch.

- Unit/integration tests.

- Static analysis and dependency checks.

- Secret scanning.

- Container/image scan.

- SBOM generation.

- Signed artifact.

- Database migration review.

- Policy/Constitution compatibility check.

- Crucible regression suite appropriate to change.

- Rollback plan.

- Post-deploy health and mission-assurance validation.

# 51. Testing Architecture

| **Test level**   | **Purpose**                                                                              |
|------------------|------------------------------------------------------------------------------------------|
| Unit             | Domain logic and deterministic components.                                               |
| Component        | Service/module behaviour with controlled dependencies.                                   |
| Integration      | Database, event bus, realtime, identity and external adapters.                           |
| Simulation       | Digital Twin events and complete incident flows.                                         |
| Hardware-in-loop | Real cameras, access devices, sensors and Edge hardware.                                 |
| AI evaluation    | Model accuracy, robustness, latency and site conditions.                                 |
| Security         | Threat modelling, scanning, authorised penetration tests and Crucible.                   |
| Performance      | Stream count, event throughput, command latency, storage and failover.                   |
| Chaos/recovery   | Network loss, Edge failure, database failover, degraded cameras, lost external services. |
| Site acceptance  | Operational scenarios with real staff and configured playbooks.                          |

# 52. Sentinel Simulator

Build the simulator early. It should generate camera events, access events, sensors, field locations, field reports, cyber events, network failures, device failures and entire scenario sequences. This allows Command, Fusion, Response and Case development before physical deployment hardware is available.

# 53. Performance and Security Metrics

## 53.1 Detection

- Precision, recall and false-negative rate.

- False-positive rate and false alarms per 100 camera-hours.

- Per-event confusion matrix.

- Detection latency P50/P95/P99.

## 53.2 Tracking

- Track continuity.

- Track loss.

- ID switches.

- Cross-camera association accuracy.

- Last-verified-observation freshness.

## 53.3 Response

- Mean time to detect.

- Mean time to acknowledge.

- Mean time to dispatch.

- Mean time to arrive.

- Mean time to stabilise.

- Mean time to close.

- Playbook execution success rate.

## 53.4 Infrastructure

- Camera/Edge/platform uptime.

- Network availability.

- Event-bus delay.

- Video frame loss.

- Storage health.

- Evidence upload backlog.

- Notification and Whisper delivery/acknowledgement.

## 53.5 Crucible

- Scenario count and coverage.

- Prevented vs detected vs missed test scenarios.

- Critical attack paths remaining.

- Mean remediation time.

- Regression pass rate.

- Unknown-attack hypothesis count.

- Assumptions without current test coverage.

**PART V — DELIVERY, ASSURANCE & OPERATIONS**

How Sentinel should be built in phases and accepted as a real protective system.

# 54. Phased Implementation Roadmap

| **Phase**                                    | **Build focus**                                                                                                                        | **Exit condition**                                                                                         |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| Phase 0 — Foundation                         | Domain model, threat model, event schema, identity, site model, Constitution, Decision Ledger, simulator, audit, observability, CI/CD. | A full simulated incident can be created, correlated, authorised, responded to and closed without cameras. |
| Phase 1 — Protective Core                    | Command, Field, protected-user app, Guest Protection PWA/session model, incident engine, map, realtime, dispatch, notifications, basic Whisper, patrols.                   | Real users can create and manage an incident end to end.                                                   |
| Phase 2 — Edge & CCTV                        | Edge runtime, ONVIF/RTSP, camera registry, health, live viewing, recording references, zones.                                          | Real test cameras operate reliably through Edge and Command.                                               |
| Phase 3 — Vision & Fusion                    | Person/vehicle tracking, zone analytics, tamper, first behavioural models, Fusion hypotheses and contradictory evidence.               | Multi-source correlation demonstrably outperforms isolated alerts.                                         |
| Phase 4 — Pursuit, Case & Evidence           | Cross-camera pursuit, vehicle intelligence, identity candidate workflow, CaseGraph, immutable evidence, authority package.             | High-threat case can be tracked, explained and exported with provenance.                                   |
| Phase 5 — Cyber, Shield & Controlled Reality | Zero-trust hardening, cyber ingestion, threat hunting, device trust, AI integrity, defender-controlled investigative environments.     | Platform detects and contains authorised cyber scenarios while preserving investigation quality.           |
| Phase 6 — Crucible & Chimera                 | Attack graph, scenario library, Digital Twin security tests, novel hypotheses, permanent regression.                                   | Security failures automatically create findings, fixes and repeatable adversarial tests.                   |
| Phase 7 — Critical-Site Hardening            | Redundant Edge, offline Command, secondary communications, advanced access/perimeter, high availability, disaster recovery.            | Critical site passes full operational and recovery exercise.                                               |
| Phase 8 — Advanced Intelligence              | Campaign memory, advanced cross-camera research, richer OpenIntel/DarkWatch, sophisticated model ensemble, large multi-site command.   | Advanced capabilities admitted only after measured evidence supports production use.                       |

# 55. Team Structure

| **Discipline**                  | **Initial responsibility**                                                                    |
|---------------------------------|-----------------------------------------------------------------------------------------------|
| Product / Security Architecture | Doctrine, scope, policy, operational model, acceptance criteria.                              |
| Core Backend                    | Identity, events, incidents, policy, case, evidence, APIs.                                    |
| Frontend / Command              | Command, admin, maps, realtime operational UI.                                                |
| Mobile                          | Field, protected-user and Guest Protection mobile/PWA experiences.                                                        |
| Edge / Video                    | Device integration, local runtime, streaming and buffering.                                   |
| AI/ML                           | Vision, evaluation, calibration, model registry and security testing.                         |
| Cybersecurity                   | Zero trust, threat modelling, CI security, Shield, Crucible and incident readiness.           |
| SRE / Infrastructure            | Cloud, databases, event bus, observability, deployment and recovery.                          |
| QA / Simulation                 | Scenario automation, integration, performance, acceptance and regression.                     |
| Privacy / Legal / Operations    | Authority model, retention, biometric/location rules, agency integration and site procedures. |

# 56. Acceptance Gates

## 56.1 Feature acceptance

- Functional requirement demonstrated.

- Authorisation and audit behaviour demonstrated.

- Failure modes tested.

- Relevant Crucible scenarios pass.

- Observability exists.

- Rollback or safe degradation exists.

- Documentation and operational ownership assigned.

## 56.2 Site acceptance

> DISCOVERED → BASELINED → CALIBRATED → DRILLED → VERIFIED → SENTINEL READY

A site should not be called ready because software installation completed. Readiness requires device inventory, camera/sensor baselines, AI calibration, playbook drills, communications testing, failure/recovery testing, privacy configuration and operator training. Sites using Guest Protection must additionally verify no-install entry, QR/NFC lifecycle, temporary-session expiry, location-permission degradation, hospitality integration failure modes, guest-facing acknowledgements and the site's actual responder procedures.

# 57. Deployment Tiers

| **Tier**              | **Typical characteristics**                                                                                                                                                          |
|-----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Sentinel Essential    | Single/few sites, basic Edge, Command, Field, optional Guest Protection profile, camera integration, incident management, core Fusion.                                                                                  |
| Sentinel Professional | Redundant Edge, richer Vision, access integration, perimeter, advanced field operations, stronger mission assurance.                                                                 |
| Sentinel Critical     | High availability, redundant network/Edge, offline command capability, advanced communications, stricter approvals, mature evidence, full Crucible exercises and recovery programme. |

# 58. Operational Governance

## 58.1 Change control

- Constitution changes require exceptional approval.

- Whisper definitions and protocols have versioned lifecycle and testing.

- AI model changes require registry update and evaluation.

- Playbooks require owner, version, effective date and authority.

- Evidence retention changes are audited and cannot alter already preserved legal holds.

- Crucible production-test permissions are explicit and narrow.

## 58.2 Two-person controls

Some actions should require two independently authorised people or equivalent dual control, including exceptional tracking powers, high-level Controlled Reality activation, disabling critical security protection, exporting restricted biometric evidence, modifying evidence retention under legal hold, and altering core Constitution rules.

# 59. Key Risks and Mitigations

| **Risk**                                       | **Why it matters**                                                 | **Design response**                                                                                         |
|------------------------------------------------|--------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
| Overconfidence in AI                           | False certainty can create harmful response.                       | Separate confidence/severity, human verification, contradictory evidence, model registry, site calibration. |
| Sentinel becomes single point of compromise    | A platform with broad security authority is valuable to attackers. | Zero trust, service separation, Constitution, Black Box, recovery plane, device trust.                      |
| Alert overload                                 | Operators ignore noisy systems.                                    | Fusion, false-alarm metrics, prioritisation, mission context, continuous tuning.                            |
| Privacy overreach                              | Location/identity intelligence can become abusive.                 | Purpose limitation, authority classification, need-to-know, retention, audit, legal review.                 |
| Attackers learn discreet signals               | Compromised Whisper set becomes dangerous.                         | Organisation-specific signals, compartmentalisation, rotation, combined modalities, anti-spoofing.          |
| Controlled environment affects real production | Poor isolation could create additional risk.                       | Dedicated boundary, explicit approval, no production pivot, full session evidence.                          |
| Adversarial testing damages production         | Autonomous testing becomes attack.                                 | Crucible execution levels and Digital Twin first.                                                           |
| Evidence challenged                            | Poor provenance or mutable records weaken cases.                   | Immutable originals, hashes, chain of custody, system-health records and reproducible exports.              |

# 60. First Build Milestones

1\. Freeze domain vocabulary and Constitution principles.

2\. Create repository, CI/CD, coding standards, threat model and secure development baseline.

3\. Implement organisation/site/identity model and policy engine.

4\. Implement normalised event contract and simulator.

5\. Implement incident, timeline, Command and Field minimum flow.

6\. Implement Whisper Studio data model and one safe device-action modality before adding AI gesture/voice recognition.

7\. Implement Edge device registry and first ONVIF camera integration.

8\. Add evidence vault foundation and Decision Ledger before advanced AI.

9\. Add Fusion with rule-based correlation before introducing complex learned reasoning.

10\. Build Digital Twin and Crucible regression framework before activating high-consequence automation.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Recommended first engineering proof</strong><br />
The first serious proof should not be an impressive violence-detection demo. It should demonstrate one complete protected workflow: a simulated multi-source threat enters the event bus, Fusion correlates it, the Constitution authorises a response, Command receives it, a Field user acknowledges discreetly, evidence is preserved, and the Decision Ledger explains every step.</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

**APPENDICES**

Schemas, operational definitions and standards references.

# Appendix A — Whisper Configuration Schema

| **Field**               | **Purpose**                                                        |
|-------------------------|--------------------------------------------------------------------|
| signal_id               | Stable identifier.                                                 |
| organisation_id         | Tenant boundary.                                                   |
| name                    | Organisation-facing signal name.                                   |
| classification          | General, Field, Supervisor, Command, High Security or compartment. |
| allowed_roles           | Who may intentionally use it.                                      |
| allowed_sites/zones     | Where it is meaningful.                                            |
| modalities              | Voice, sound, gesture, motion, device, wearable, context.          |
| combination_expression  | Logical/temporal composition.                                      |
| recognition_thresholds  | Per-modality and combined confidence.                              |
| anti_spoof_requirements | Liveness, trusted device, freshness, context.                      |
| intent                  | Normalised meaning produced by Whisper.                            |
| response_mode           | Standard, Discreet or Silent.                                      |
| protocol_id             | Response playbook mapping.                                         |
| confirmation            | Haptic, hidden visual, none, secure acknowledgement.               |
| version/status          | Lifecycle and rotation.                                            |
| approval                | Creator, reviewer, approver, effective date.                       |

# Appendix B — Playbook Definition Schema

| **Field**              | **Purpose**                                      |
|------------------------|--------------------------------------------------|
| playbook_id / version  | Stable versioned response object.                |
| incident families      | Which incident types may use it.                 |
| entry conditions       | Threat state, severity, evidence and context.    |
| response mode          | Standard, Discreet or Silent.                    |
| actions                | Ordered or conditional tasks.                    |
| approval requirements  | Human/dual approval before selected actions.     |
| timeouts               | Expected acknowledgement/action timing.          |
| fallbacks              | Alternative communication, team or service path. |
| external connectors    | Authorised agency/monitoring interfaces.         |
| evidence actions       | Preservation and case requirements.              |
| closure conditions     | When playbook ends or transitions.               |
| owner / effective date | Governance and review.                           |

# Appendix C — Evidence Manifest

> case_id  
> incident_id  
> package_id  
> created_at  
> authorising_user  
> recipient / authority_reference  
> items\[\]:  
> evidence_id  
> source  
> original_hash  
> derived_from  
> classification  
> captured_at  
> stored_at  
> custody_events  
> model/config references where applicable  
> manifest_hash  
> export_reason

# Appendix D — High-Security Metrics Catalogue

| **Domain**        | **Metrics**                                                                                         |
|-------------------|-----------------------------------------------------------------------------------------------------|
| Vision            | Precision, recall, FNR, FPR, false alarms / 100 camera-hours, detection P95/P99.                    |
| Tracking          | Continuity, ID switches, cross-camera association, last-observation freshness.                      |
| Whisper           | Recognition accuracy, accidental trigger rate, spoof-test pass rate, delivery/acknowledgement time. |
| Fusion            | Hypothesis precision, escalation correctness, contradiction discovery, source diversity.            |
| Response          | Detect/acknowledge/dispatch/arrive/stabilise/close times, playbook success.                         |
| Mission Assurance | Protected-mission coverage, degraded duration, dependency failure recovery.                         |
| Cyber/Shield      | Time to detect, time to contain, persistence-hunt coverage, compromised-device quarantine time.     |
| Crucible          | Scenario coverage, failed paths, regression pass, remediation time, untested assumptions.           |
| Evidence          | Hash verification, custody completeness, export reproducibility, clock-health coverage.             |
| Platform          | Availability, event lag, stream loss, storage health, recovery objectives.                          |

# Appendix E — Standards and Primary References

| **Reference**                                               | **How Sentinel uses it**                                                                                                     |
|-------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| NIST SP 800-207 — Zero Trust Architecture                   | Resource-centric zero-trust principles; no implicit trust based solely on network location.                                  |
| NIST Cybersecurity Framework 2.0                            | Govern, Identify, Protect, Detect, Respond and Recover outcomes for cybersecurity risk management.                           |
| NIST SP 800-61 Rev. 3                                       | Current incident-response recommendations integrated with CSF 2.0.                                                           |
| NIST SP 800-218 — Secure Software Development Framework 1.1 | Secure-development practices integrated through the software lifecycle.                                                      |
| NIST SP 800-115                                             | Technical security testing and assessment guidance.                                                                          |
| NIST SP 800-86                                              | Forensic techniques integrated with incident response; not a substitute for legal advice.                                    |
| NIST AI Risk Management Framework 1.0                       | Governance and measurement of AI risk across the lifecycle; revision activity should be monitored.                           |
| MITRE ATT&CK Enterprise                                     | Adversary tactics and techniques for enterprise environments; use as scenario-library input rather than a complete boundary. |
| MITRE ATLAS                                                 | Adversarial tactics and techniques against AI-enabled systems, including predictive, generative and agentic systems.         |
| ONVIF Profile T                                             | Advanced IP-video streaming, metadata, motion/tamper events and related controls.                                            |
| ONVIF Profile M                                             | Standardised analytics metadata and events, including analytics integration paths.                                           |
| IETF RFC 9420 — Messaging Layer Security                    | End-to-end secure asynchronous group key establishment with forward secrecy and post-compromise security.                    |
| Nigeria Data Protection Act 2023 / NDPC                     | Privacy, lawful processing, accountability, security, minimisation and data-subject rights for Nigerian deployments.         |
| CISA threat-hunting and secure-by-design guidance           | Operational reference for proactive hunt concepts and manufacturer responsibility for secure defaults.                       |

# Appendix F — Glossary

| **Term**           | **Definition**                                                                                                                                                         |
|--------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Controlled Reality | A defender-controlled environment intentionally constructed so an adversary interacts with operationally real controlled assets while genuine assets remain protected. |
| Digital Twin       | A simulation/test environment used by Sentinel and authorised testers, not a real adversary.                                                                           |
| Event              | Immutable observation from a source.                                                                                                                                   |
| Hypothesis         | Fusion interpretation that explains one or more events and remains subject to contradictory evidence.                                                                  |
| Incident           | Operational object created when a threat or safety condition requires coordinated handling.                                                                            |
| Mission            | A protected objective such as vault observation, perimeter protection or field communication.                                                                          |
| Playbook           | Versioned authorised response logic for an incident class.                                                                                                             |
| Protocol           | Organisation-defined action sequence invoked from an intent or playbook.                                                                                               |
| Whisper Intent     | Normalised meaning inferred from an organisation-configured discreet signal.                                                                                           |
| Track              | Temporary anonymous continuity identifier for a person or vehicle.                                                                                                     |
| Candidate Identity | Possible identity association requiring verification.                                                                                                                  |
| Campaign           | Long-lived grouping of incidents and adversary indicators that may represent a continuing operation.                                                                   |
| Constitution       | Hardened policy layer defining what Sentinel is authorised to do.                                                                                                      |
| Decision Ledger    | Record of evidence, model/rule versions, policy, confidence, approvals and action for high-value decisions.                                                            |
| Black Box          | Independently protected operational recorder.                                                                                                                          |
| Crucible           | Continuous adversarial assurance and scenario-testing subsystem.                                                                                                       |
| Chimera            | Novel attack hypothesis generator used by Crucible.                                                                                                                    |
| Mission Assurance  | Assessment of whether protective objectives remain achievable given current system state.                                                                              |
| Guest Protection   | Temporary, privacy-scoped protective capability for hospitality, tourism, events, campuses, healthcare and other public-facing environments, available without requiring a permanent Sentinel account. |

# Appendix G — Guest Protection Configuration Schema

A Guest Protection profile should be exportable as a versioned configuration object.

```text
guest_profile_id
organisation_id
name
deployment_type
allowed_sites
entry_channels
guest_intents
whisper_signal_sets
response_protocols
responder_groups
location_policy
guardian_journey_policy
dependant_policy
qr_nfc_policy
external_context_adapters
notification_policy
silent_acknowledgement_policy
consent_text_version
privacy_policy_version
retention_policy
offline_fallback
activation_window
version
status
created_by
approved_by
effective_at
retired_at
```

Recommended lifecycle:

```text
DRAFT
→ TESTING
→ DRILLED
→ APPROVED
→ ACTIVE
→ DEGRADED / SUSPENDED
→ RETIRED
```

Changes to guest signals, privacy policy, responder routing or retention rules are versioned and audited. A live profile never changes silently underneath an active incident or guardian journey.

# Closing Architecture Statement

Sentinel should be built as a protective operating system rather than a collection of alarms. Its strongest differentiator is the combination of multi-source understanding, discreet human communication, policy-governed response, continuing lawful pursuit, forensic case development, platform self-protection and continuous adversarial self-testing.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Final design principle</strong><br />
Sentinel must protect against three adversaries simultaneously: the attacker it knows, the attacker it has not yet imagined, and the possibility that Sentinel itself is wrong.</th>
</tr>
</thead>
<tbody>
</tbody>
</table>

**SUPPLEMENT — DETAILED ENGINEERING IMPLEMENTATION BLUEPRINT**

A deeper implementation plan describing concrete services, workflows, data boundaries, security controls and release sequencing.

# 61. Implementation Principles

The implementation should preserve the product doctrines in code. Domain logic must distinguish events from conclusions, intelligence from authority, and detection from response. Every service that can cause a meaningful operational action must produce enough evidence for the Decision Ledger to explain why that action occurred.

- Prefer deterministic domain rules for authority, approvals, policy and state transitions. AI models may inform these rules but cannot silently replace them.

- Use append-only operational events and explicit compensating records rather than rewriting security history.

- Treat every external integration as untrusted until authenticated, authorised, validated and mapped to a source-trust state.

- Keep evidence bytes outside ordinary transactional tables and protect originals using immutable-capable storage and independent integrity records.

- Design every critical workflow for offline, degraded and recovery states before calling the feature complete.

- Make site-specific configuration data, model thresholds and Whisper signals deployable independently of application releases, but always versioned and signed where appropriate.

# 62. Human Roles, Clearance and Operational Authority

| **Role**                        | **Typical authority**                                                                                                        |
|---------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| Platform Security Administrator | Platform infrastructure, tenant onboarding and protected policy operations. No automatic right to inspect customer evidence. |
| Organisation Security Director  | Owns organisational policy, high-level playbooks, site security posture and selected high-authority approvals.               |
| Site Commander                  | Operational responsibility for one or more sites during an incident.                                                         |
| Control-Room Operator           | Monitors alerts, incidents, cameras and Field state; acts within assigned authority.                                         |
| Dispatcher                      | Assigns teams and resources without necessarily receiving full investigative intelligence.                                   |
| Field Supervisor                | Manages teams, patrols, welfare and operational tasking.                                                                     |
| Field Operative                 | Receives need-to-know tasks, uses Whisper, captures observations and evidence.                                               |
| Investigator                    | Accesses authorised case/evidence material and develops hypotheses.                                                          |
| Evidence Custodian              | Controls evidence export, retention holds and custody processes.                                                             |
| AI Assurance Officer            | Approves model/site admission, calibration and performance review.                                                           |
| Crucible Operator               | Runs authorised adversarial tests within assigned execution level.                                                           |
| Privacy / Compliance Reviewer   | Reviews lawful basis, data minimisation, retention and restricted-intelligence operations.                                   |
| Auditor                         | Read-only access to approved operational and compliance records.                                                             |

## 62.1 Permission model

Use role-based access control for broad job functions and attribute-based constraints for site, shift, incident, clearance, purpose and device state. A user may have the role “Operator” but still be unable to view biometric evidence, a different site, an unrelated investigation or a compartmented Whisper definition.

> ALLOW action WHEN  
> role permits action  
> AND organisation matches  
> AND site/incident scope matches  
> AND clearance \>= object classification  
> AND device trust acceptable  
> AND purpose is valid  
> AND Constitution does not require additional approval

# 63. Workflow Orchestration Engine

Response playbooks, approval gates, external escalation and long-running incident tasks need a durable workflow engine. The implementation should support timers, retries, compensating actions, human approvals, idempotent external calls and resumable state after service restarts.

## 63.1 Workflow primitives

- Task assignment.

- Human approval.

- Two-person approval.

- Wait for acknowledgement.

- Conditional branch.

- Timer and deadline.

- Retry with backoff.

- Fallback channel.

- Parallel actions.

- Evidence-preservation step.

- External connector invocation.

- Manual override with reason.

- Escalation.

- Compensation/rollback where safe.

## 63.2 Example response workflow

> INCIDENT SEV-1 / SILENT  
> 1. Preserve relevant video \[automatic\]  
> 2. Notify Site Commander \[automatic\]  
> 3. Identify nearest qualified teams \[automatic\]  
> 4. Dispatch team \[policy allows automatic or requires approval\]  
> 5. Await field acknowledgement \[20 sec\]  
> 6. If no acknowledgement → alternate team + supervisor  
> 7. Prepare external package \[automatic\]  
> 8. External notification \[approval/connector policy\]  
> 9. Maintain pursuit until authority handoff or commander closure

# 64. Event Ingestion and Source Adapters

All source adapters produce the same internal event contract. Adapters are responsible for authentication, timestamp capture, source identity, schema conversion, rate control and initial integrity checks, but they should not make high-level threat decisions.

| **Adapter family** | **Examples**                                               | **Output**                                                      |
|--------------------|------------------------------------------------------------|-----------------------------------------------------------------|
| Video              | ONVIF events, analytics metadata, Edge Vision              | Object/motion/tamper/track events.                              |
| Access             | Door controller, credential system, visitor system         | Access granted/denied, forced door, credential/context events.  |
| Field              | Field app, wearable, observation session                   | Human observation, status, Whisper result, evidence references. |
| Sensor             | Motion, glass, fire, environmental, perimeter              | Typed physical-sensor events.                                   |
| Cyber              | Identity provider, endpoint, network, cloud, API telemetry | Authentication, device, network and security events.            |
| Intelligence       | OpenIntel, DarkWatch, approved feeds                       | Structured lead/indicator events with authority metadata.       |
| External Response  | Monitoring provider or authorised agency interface         | Delivery, acknowledgement and reference events.                 |

## 64.1 Idempotency and duplicate control

Every external source event should have a stable source identifier where possible. Sentinel generates an idempotency key from source identity, event identity and time window. Duplicate raw events can be linked to the original without erasing the fact that multiple deliveries occurred.

# 65. Fusion Implementation

## 65.1 First version

Do not start Fusion as a giant end-to-end learned model. Version one should use transparent rules, temporal/spatial correlation, source trust, confidence aggregation and explicit hypotheses. This makes it testable and gives a baseline against which later learned reasoning can be measured.

## 65.2 Correlation dimensions

- Time overlap and sequence.

- Physical proximity and route connectivity.

- Shared temporary person/vehicle tracks.

- Common device/account or credential.

- Common organisation/site/zone.

- Source independence and trust.

- Historical campaign similarity.

- Operational schedule and expected behaviour.

- Field observation and commander verification.

- Contradictory evidence and alternative hypotheses.

## 65.3 Hypothesis record

> hypothesis_id  
> incident_candidate_id  
> type  
> state  
> supporting_event_ids\[\]  
> contradicting_event_ids\[\]  
> source_diversity  
> threat_probability  
> potential_impact  
> operational_severity  
> confidence_explanation  
> created_at / updated_at  
> rule_or_model_versions\[\]

# 66. Command UI Implementation

Command must be designed around operator cognitive load. The map, incident queue and incident workspace are separate visual responsibilities but remain synchronised. Selecting an incident should scope cameras, field units, timelines and controls to that incident unless the operator deliberately changes context.

## 66.1 Command screen states

- Normal operations: map, scheduled patrols, device/mission health.

- Elevated: prioritised alert with supporting evidence and contradiction indicator.

- Critical: incident workspace takes visual precedence; only required controls remain prominent.

- Degraded operations: mission-impact banner explains what protection is unavailable and which fallback is active.

- Recovery: explicit confirmation that restored services are trusted before their evidence regains normal weight.

## 66.2 Operator safeguards

- No destructive action from a single ambiguous button.

- Critical controls show consequence before execution.

- Policy-required approval appears in workflow instead of as a separate administrative process.

- Every manual override requires reason and is written to the Decision Ledger.

- Evidence and intelligence classifications are visually distinct.

- Predictions are visually different from last verified observations.

# 67. Field and Mobile Implementation

## 67.1 Separate applications

Field and protected-user functions should be separate apps or strongly separated application modes because their permissions, data retention and threat models differ materially. Field devices are managed operational assets; protected-user devices are user-controlled and should receive much less privileged information.

## 67.2 Field offline store

- Current assignment and minimum incident brief.

- Site map subset.

- Patrol route/checkpoints.

- Trusted emergency contacts and procedures.

- Pending secure messages.

- Evidence awaiting upload with local encryption.

- Device/identity state and policy expiry.

## 67.3 Whisper recognition placement

Where possible, simple device/wearable actions should be recognised locally. Camera gestures or site acoustic signals may be recognised at Edge. Voice recognition may use local or trusted service processing according to privacy and latency requirements. The output entering the core is a signed recognition result with modality evidence, confidence, device/source trust and context.

# 67A. Guest Protection Implementation

Guest Protection shares the core identity, event, incident, Response, Whisper and Evidence services but has a deliberately lower-trust client and a temporary data model.

## 67A.1 Request path

```text
guest-web
   ↓ HTTPS
API gateway
   ↓
guest-session validation
   ↓
guest-protection module
   ↓
normalised Event
   ↓
Fusion / Constitution
   ↓
Incident + Response
   ↓
Command / Field
```

The guest client never talks directly to camera, Edge, Case, Evidence or responder services.

## 67A.2 Repository additions

Recommended additions to the monorepo:

```text
apps/
├─ guest-web/
│  ├─ entry/
│  ├─ intents/
│  ├─ guardian/
│  ├─ status/
│  └─ privacy/
│
packages/
├─ guest-protection-contracts/
├─ guest-session/
└─ hospitality-adapters/
│
tests/
├─ guest-protection/
└─ hospitality-simulation/
```

The server implementation can initially remain within `services/core-api` under a `guest-protection` bounded module.

## 67A.3 Database separation

Guest transactional context should be logically separated from long-lived identity and evidence data.

Suggested tables:

```text
guest_sessions
guest_session_tokens
guest_context_links
visitor_passes
guest_consents
guest_intent_requests
guardian_journeys
guardian_journey_updates
dependant_links
guest_location_snapshots
guest_notifications
guest_entry_points
hospitality_adapter_links
```

Incident-linked data that becomes evidence is referenced into Sentinel Evidence rather than left as mutable guest-session state.

## 67A.4 Session-expiry worker

A scheduled worker should:

- Expire completed visits.
- Revoke stale activation tokens.
- Stop guardian journeys that reached explicit expiry and create the appropriate review event where needed.
- Delete or anonymise temporary location according to policy.
- Preserve records under active incident/evidence/legal hold.
- Emit auditable retention events.

Deletion and retention behaviour should be tested as carefully as event creation.

## 67A.5 Guest simulator

The Sentinel Simulator should include synthetic guest journeys:

```text
normal visitor entry
medical request
silent assistance request
location denied
lost dependant
guardian journey overdue
network interruption
replayed QR
expired visitor pass
booking adapter unavailable
false Whisper recognition
guest checks out during open incident
```

These become permanent acceptance and regression cases.

# 68. Edge Deployment Profiles

| **Profile**           | **Typical use**               | **Capabilities**                                                                                                                   |
|-----------------------|-------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| Edge Micro            | Small site / low camera count | Device gateway, event normalisation, health, limited local rules, minimal video buffering.                                         |
| Edge Vision           | Medium site                   | GPU-assisted multi-stream analytics, local event bus, incident video buffer, camera orchestration.                                 |
| Edge Resilient        | High-security site            | Redundant nodes, replicated local state, offline Command subset, secondary uplink, stronger local storage.                         |
| Edge Critical Cluster | Large critical facility       | Multiple GPU/compute nodes, HA control plane, segmented camera networks, local evidence cache and local Fusion subset if required. |

## 68.1 Capacity planning

Edge sizing must use measured stream resolution, frame rate, codec, model complexity, number of simultaneous models, retention window and required latency. Procurement should not be based on an abstract “cameras per GPU” number copied from a vendor demonstration.

# 69. Vision Runtime Implementation

## 69.1 Stream graph

> INPUT STREAM  
> → decode  
> → resize/colour conversion  
> → primary detection  
> → tracker  
> → optional secondary classifiers  
> → zone/line analytics  
> → behaviour window  
> → event formatter  
> → evidence clip trigger  
> → telemetry

## 69.2 Model ensemble rules

High-threat detection may use multiple models or modalities, but ensembles must remain observable. Fusion should know which models contributed, whether they share training lineage and whether their outputs are actually independent. Two models derived from the same data and failure mode should not be treated as two independent witnesses.

# 70. Cyber and Shield Implementation

## 70.1 Cyber telemetry

- Identity-provider authentication and MFA events.

- Endpoint/security-agent alerts.

- Network-flow and DNS events.

- Cloud audit logs.

- Privileged administrative operations.

- API gateway anomalies.

- Container/runtime security events.

- Edge and camera administration changes.

- Source-code/build security events for Sentinel itself.

## 70.2 Contain, preserve, hunt

For serious cyber incidents, containment must preserve enough state for investigation. Shield should support credential/session revocation, device quarantine, network restriction and service isolation while Cyber opens a hunt plan for persistence and related activity. Closure requires evidence that the environment was scoped, not merely that the visible account was blocked.

## 70.3 Recovery plane

Create an administrative recovery plane with separate credentials, strongly restricted endpoints and independent logging. It exists for the case where ordinary Command or identity systems are themselves suspect. Recovery access should be rare, heavily audited and exercised periodically.

# 71. Controlled Reality Implementation

## 71.1 Isolation model

> SUSPICIOUS SESSION  
> ↓  
> POLICY / AUTHORISATION  
> ↓  
> TRAFFIC OR IDENTITY DIVERSION  
> ↓  
> CONTROLLED REALITY SEGMENT  
> ├─ controlled identities  
> ├─ controlled data  
> ├─ controlled services  
> └─ full telemetry  
> ↓  
> ONE-WAY / SANITISED INTELLIGENCE EXPORT  
> ↓  
> SENTINEL CASE

## 71.2 Hard boundaries

- No route from controlled environment to real sensitive production without an explicit mediation gateway.

- No defender-controlled secret is reused in real production.

- All content presented to the adversary is catalogued and versioned.

- Analyst interventions are recorded.

- Attacker-supplied files enter isolated analysis.

- Controlled assets cannot automatically initiate unauthorised activity against external systems.

# 72. Case and Evidence Implementation

## 72.1 Storage split

Case metadata belongs in the transactional database. Large immutable evidence objects belong in object storage. Integrity hashes, manifests and custody events belong in a separate evidence metadata model with restricted write permissions. The application should never overwrite the original evidence object when generating clips or enhancements.

## 72.2 Evidence write path

> SOURCE  
> ↓  
> INGEST GATEWAY  
> ↓  
> HASH + METADATA  
> ↓  
> IMMUTABLE OBJECT STORAGE  
> ↓  
> EVIDENCE RECORD  
> ↓  
> CHAIN-OF-CUSTODY EVENT  
> ↓  
> OPTIONAL DERIVED COPY

## 72.3 Authority package generator

The generator should create a deterministic manifest, human-readable summary, timeline, evidence list, hashes, custody report, attribution status and identified investigative gaps. Package generation itself becomes a custody event, and later package versions never silently replace earlier versions.

# 73. Crucible and Chimera Implementation

## 73.1 Scenario representation

Represent scenarios as versioned graphs and declarative steps rather than free-form prose alone. Each scenario includes prerequisites, attacker goals, expected actions, signals, safety level, test environment, expected Sentinel controls and pass/fail criteria.

## 73.2 Chimera inputs

- Asset/dependency graph.

- Trust relationships.

- Current vulnerabilities and misconfigurations.

- Historical incidents and campaigns.

- MITRE ATT&CK and ATLAS technique mappings.

- Human roles and shift patterns.

- Physical routes and camera blind spots.

- Mission Assurance dependencies.

- Current degraded controls.

- Threat intelligence.

## 73.3 Finding lifecycle

> DISCOVERED → TRIAGED → OWNER ASSIGNED → FIX IN PROGRESS → RETEST → REGRESSION ADDED → CLOSED

A security finding cannot close solely because code changed. The relevant scenario or an equivalent test must pass, and a regression must remain in the suite for significant failures.

# 74. Multi-Tenant Isolation

Sentinel is likely to become multi-organisation. Isolation must exist in API authorisation, database queries, object-storage namespaces, encryption keys, realtime channels, evidence access, analytics and operational tooling. Platform support staff should not automatically inherit customer evidence access.

## 74.1 Stronger isolation options

- Dedicated encryption keys per organisation.

- Dedicated evidence buckets or prefixes with independent policies.

- Separate Edge PKI identities per organisation/site.

- Optional dedicated database/schema or deployment for Critical tier customers.

- Compartmented analytics exports.

# 75. Key and Secret Management

- Central secret manager for service/application secrets.

- Private PKI for Edge/device identity.

- Hardware-backed or managed KMS/HSM for high-value signing and encryption keys.

- Automatic certificate rotation.

- No long-lived credentials baked into applications or Edge images.

- Separate production, staging and laboratory trust roots.

- Emergency key-revocation procedure tested in Crucible.

# 76. Reliability Semantics

Security software must be explicit about delivery semantics. Events and commands may be retried, reordered or duplicated during failures. The design should therefore use idempotency keys, monotonic incident versions where appropriate, durable workflow state and clear “requested / delivered / acknowledged / executed” distinctions.

| **State**    | **Meaning**                                                                   |
|--------------|-------------------------------------------------------------------------------|
| REQUESTED    | Sentinel decided an action should be attempted.                               |
| DELIVERED    | The destination transport accepted the message.                               |
| ACKNOWLEDGED | An authorised human/device confirmed receipt.                                 |
| EXECUTED     | The requested operational action was confirmed.                               |
| FAILED       | The action did not complete.                                                  |
| UNKNOWN      | Sentinel cannot yet prove whether it completed; escalation/fallback required. |

# 77. Data Retention and Legal Holds

Retention must be policy-driven by data class, site and legal basis. Routine telemetry may have a shorter lifetime than active incident evidence. Once evidence is under legal or investigative hold, routine deletion schedules must not remove it. Retention changes are auditable policy operations.

# 78. External Integrations

| **Integration**              | **Design requirement**                                                                        |
|------------------------------|-----------------------------------------------------------------------------------------------|
| Security/monitoring provider | Authenticated API or contractual channel, delivery receipt, incident reference.               |
| Public authority             | Jurisdiction-specific authorised connector or structured handoff process.                     |
| Maps/geospatial              | Provider abstraction; do not couple core incident logic to one vendor.                        |
| Identity provider            | OIDC/SAML or equivalent enterprise integration plus local emergency/recovery strategy.        |
| Messaging                    | Multiple providers/channels with clear security classification and fallback policy.           |
| Camera/NVR                   | ONVIF/RTSP first, vendor adapter when required.                                               |
| Access control               | Event and identity adapter; avoid making access-vendor database the Sentinel source of truth. |
| Threat intelligence          | Source authority, confidence, expiry and provenance required.                                 |
| Ticketing/visitor systems    | Scoped visitor identity and site access context only.                                         |

# 79. Operational Readiness Programme

## 79.1 Before production

1\. Site security objective and threat model approved.

2\. All cameras/sensors inventoried and mapped.

3\. Edge and network capacity measured under expected load.

4\. Command and Field roles trained.

5\. Whisper signals tested for false activation and spoof resistance.

6\. Playbooks drilled with real personnel.

7\. External escalation contacts/channels verified.

8\. Evidence retention and privacy configuration approved.

9\. Digital Twin and Crucible baseline scenarios passed.

10\. Backup, offline and recovery exercises passed.

## 79.2 After production

- Weekly mission-health review for critical sites.

- Regular device and certificate health review.

- Model drift and false-alarm review.

- Whisper signal review/rotation as policy requires.

- Monthly/quarterly Crucible scenarios appropriate to tier.

- Periodic full operational exercise.

- Post-incident learning automatically creates scenarios and policy review tasks.

# 80. Initial Engineering Proofs

Before attempting the entire platform, engineering should prove the architectural risks in a controlled order.

| **Proof**                     | **Required demonstration**                                                                                                                                    |
|-------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Proof A — Incident Core       | Simulator emits multi-source events; Fusion correlates; Constitution authorises; Command receives; Field acknowledges; evidence and Decision Ledger complete. |
| Proof B — CCTV Edge           | Two or more ONVIF cameras stream through Edge, emit metadata, survive reconnect, preserve an incident clip and expose health to Mission Assurance.            |
| Proof C — Whisper             | Organisation creates a device/wearable signal in Whisper Studio, tests it, activates it, and invokes a silent protocol with authenticated acknowledgement.    |
| Proof D — Degraded Operations | WAN fails; Edge continues critical local functions; Field messages queue; central sync recovers without duplicate incident actions.                           |
| Proof E — Evidence            | Incident package exports with immutable originals, hashes, custody and reproducible manifest.                                                                 |
| Proof F — Crucible            | A simulated attack path finds a control failure, creates a finding, fix is applied, retest passes and regression remains permanent.                           |
| Proof G — Shield              | Compromised-device simulation downgrades trust and Fusion reduces that source’s evidentiary weight while mission coverage compensates.                        |

# 81. Ninety-Day Foundation Plan

| **Window**  | **Focus**                             | **Deliverables**                                                                                                                        |
|-------------|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| Weeks 1-2   | Architecture and security foundations | Repo, CI, threat model, Constitution skeleton, event schemas, organisation/site/identity model, observability.                          |
| Weeks 3-4   | Incident core                         | Incident lifecycle, workflow engine, Decision Ledger, simulator, initial Command shell.                                                 |
| Weeks 5-6   | Realtime and Field                    | Presence, secure messaging, Field assignments, acknowledgements, patrol foundation.                                                     |
| Weeks 7-8   | Whisper foundation                    | Whisper Studio, device-action modality, protocol mapping, policy checks, audit and test harness.                                        |
| Weeks 9-10  | Edge/video proof                      | First ONVIF adapter, Edge runtime, stream health, basic motion/object metadata, incident clip preservation.                             |
| Weeks 11-12 | Fusion and assurance                  | Rule-based multi-source correlation, source trust, contradictory evidence, Mission Assurance baseline, first Crucible regression suite. |
| Week 13     | Integrated demonstration              | End-to-end scenario through Command, Field, Whisper, Edge, Fusion, Evidence and Decision Ledger.                                        |

# 82. Architecture Completion Criteria

The architecture can be considered ready for full product development when the following are true:

- Product doctrine, legal boundaries and Constitution principles are approved.

- Event, incident, evidence, policy, Whisper and scenario schemas are versioned.

- The first Digital Twin exists and can replay full incidents.

- The first Edge/video proof operates with real hardware.

- Command and Field interaction has been tested with operators rather than only developers.

- The first high-threat playbooks have explicit approval and external-escalation boundaries.

- Evidence and Decision Ledger functions are complete enough to explain system behaviour.

- Crucible can turn a failed scenario into a tracked finding and permanent regression.

- Mission Assurance can distinguish a healthy platform from a degraded protection objective.

- A written privacy and biometric-governance review exists for the first deployment jurisdiction.

<table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Engineering north star</strong><br />
Do not measure progress by the number of Sentinel modules with screens. Measure progress by complete protected workflows that still behave correctly when sensors lie, networks fail, humans make mistakes and adversaries deliberately try to manipulate the system.</th>
</tr>
</thead>
<tbody>
</tbody>
</table>
