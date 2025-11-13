USB Security System: Unified Technical Specification
Executive Summary
This document specifies a comprehensive USB security system comprising two primary components: a Gateway that securely processes and packages USB content, and an Agent that provides controlled access to encrypted USB data. The system implements defence-in-depth security through hardware attestation, encrypted storage, policy-based access control, and comprehensive audit  .

1. System Architecture Overview
1.1 Core Components
•	 
•	Gateway     Service: Windows service for USB device processing, encryption, and     packaging 
•	Agent     Service: Endpoint service for secure file presentation and user     interaction 
•	Key     Management System (KMS): HashiCorp Vault with HSM integration for     cryptographic operations 
•	Policy     Engine: Open Policy Agent (OPA) for dynamic policy enforcement 
•	Attestation     Infrastructure: TPM-based device attestation and MDM compliance     verification
1.2 Security Architecture Principles
•	 
•	Zer  Trust: Every component must authenticate and be authorized for each     operation 
•	Encryption     at Rest: All USB content encrypted with ephemeral Content Encryption     Keys (CEK) 
•	Hardware     Root of Trust: TPM-backed attestation for device and service integrity 
•	Fail-Secure:     System defaults to denial of access on any security control failure 
•	Comprehensive     Audit: Immutable logging of all security-relevant operations

2. Gateway Flow: USB Processing Pipeline
2.1 Device Detection & Hardware Claiming
2.1.1 Detection Mechanism
•	 
•	Deploy     Windows Filter Manager minifilter driver (signed) for reliable     volume attach/detach event monitoring 
•	Monitor     Win32_VolumeChangeEvent EventType=2 via WMI for USB insertion events 
•	Extract     unique device identifiers: Serial Number, Volume GUID, Product IDs 
•	Implement     rate limiting per device UID within configurable time windows (default: 30     seconds)
 
2.1.2 Exclusive Volume Locking
•	 
•	Critical     Requirement: Implement hard enforcement device claiming 
•	In     pre-create callback, execute IRP_MJ_CREATE with deny-share flags t  prevent auto-mount 
•	Open     device handle with no sharing flags (FILE_SHARE_NONE) for     kernel-level exclusive access 
•	Maintain     exclusive lock throughout entire processing pipeline until job     finalization 
•	This     prevents race conditions, malware access, and user interference during     processing
2.1.3 Device Metadata Collection
Required Metadata Fields:
- device_serial: USB device serial number
- volume_guid: Windows volume GUID
- product_id: USB product identifier
- device_capacity: Total storage capacity
- filesystem_type: NTFS/FAT32/exFAT detection
- insertion_timestamp: ISO 8601 UTC timestamp
- hostname: Processing gateway hostname
- gateway_version: Software version identifier
2.2 Job Lifecycle Management
2.2.1 Job Initialization
•	 
•	Generate     job_id using UUID4 for guaranteed uniqueness 
•	Create     job persistence directory: %ProgramData%\SMX\Jobs\<job_id>\ 
•	Initialize     three core job components:    
o	metadata.json:      Static device and job metadata  
o	state.json:      Current processing state with transitions  
o	logs.jsonl:      Append-only timestamped log entries with sequence numbers 
2.2.2 State Management
Job States:
- INITIALIZED: Job created, metadata collected
- ENUMERATING: File system enumeration in progress
- POLICY_CHECK: Pre-scan policy validation
- SCANNING: Malware analysis in progress
- PACKAGING: Encryption and manifest creation
- SUCCESS: Job completed successfully
- FAILED_POLICY: Policy violation detected
- QUARANTINED: Malware or error detected
- FAILED: Unrecoverable error occurred
2.2.3 Atomic Operations & Recovery
•	 
•	Use     temporary files with atomic rename for metadata updates 
•	Implement     write-ahead logging for state transitions 
•	On     system restart, automatically resume incomplete jobs by reading state.json 
•	Implement     configurable retention policies for completed jobs (default: 90 days)
2.3 File Enumeration & Canonicalization
2.3.1 Robust Path Processing
•	 
•	Leverage     Windows PathCch API for Unicode normalization (NFC/NFKC) 
•	Resolve     reparse points safely with circular reference detection 
•	Sanitize     paths: remove ".." traversal attempts, illegal characters,     reserved names 
•	Generate     deterministic, sorted file listing for reproducible processing
2.3.2 NTFS Alternate Data Streams (ADS) Handling
•	 
•	Security     Critical: Use BackupRead API to enumerate all ADS 
•	Implement     ADS whitelist for known legitimate streams (:$DATA, :Zone.Identifier) 
•	Default     Deny: Drop all unknown ADS to prevent hidden payload execution 
•	Log     all ADS discoveries with stream names and sizes
2.3.3 File System Edge Cases
•	 
•	Handle     maximum path length limitations (260 chars standard, 32K with long path     support) 
•	Identify     and exclude device nodes, named pipes, and special file types 
•	Implement     size-based filtering for extremely large files (configurable threshold)
2.4 Policy Enforcement Engine
2.4.1 Open Policy Agent (OPA) Integration
•	 
•	Implement     policy signature verification using Ed25519 signatures 
•	Support     live policy updates via GitOps with version-based rollback protection 
•	Cache     policies in memory only; fail-closed on cache miss
 
2.4.2 Policy Decision Points
Evaluated Policies:
- Total file count limits
- Individual file size limits  
- Total USB capacity limits
- File extension blacklist/whitelist
- Archive depth restrictions (ZIP, RAR, 7z)
- User-Based Access Control (UBAC) rules
- Time-based access restrictions
- Content-based classification rules
2.4.3 Policy Violation Handling
•	 
•	On     policy failure, immediately update state.json to FAILED_POLICY 
•	Log     detailed policy violation information including rule name and violation     details 
•	Maintain     device lock for potential remediation or VM-based analysis 
•	Generate     user-friendly policy violation notifications
2.5 Malware Analysis Pipeline
2.5.1 Static Analysis
•	 
•	Primary     Engine: Microsoft Defender integration via Windows Defender APIs 
•	Secondary     Engine: ClamAV for additional coverage 
•	Record     comprehensive scan results:    
o	Verdict:      CLEAN/INFECTED/ERROR/TIMEOUT  
o	Engine      name and signature version  
o	Threat      names and affected file paths  
o	Scan      duration and resource usage 
2.5.2 Dynamic Analysis (Advanced Configuration)
•	 
•	Submit     suspicious files to Cuckoo Sandbox for behavioural analysis 
•	Implement     file upload size limits and timeout controls 
•	Support     air-gapped environments with offline analysis capabilities
2.5.3 Threat Response
•	 
•	On     malware detection, transition to QUARANTINED state 
•	Preserve     device lock for optional VM-based detonation 
•	Generate     detailed incident reports with file hashes and detection metadata 
•	Support     integration with SIEM systems for threat intelligence
2.6 Cryptographic Packaging
2.6.1 Content Encryption Key (CEK) Operations
•	 
•	Generate     ephemeral AES-256-GCM CEK for each job using cryptographically secure RNG 
•	Encrypt     all file content with generated CEK 
•	Immediate     Wrapping: Send CEK to HashiCorp Vault Transit engine for HSM-based     wrapping 
•	Use     PKCS#11 HSM integration for Key Encryption Key (KEK) operations 
•	Securely     wipe plaintext CEK from memory immediately after wrapping
2.6.2 Manifest Creation & Integrity
•	 
•	Generate     SHA-256 digest for each encrypted file blob 
•	Create     comprehensive manifest including:    
o	File      paths and original metadata  
o	SHA-256      digests of encrypted content  
o	File      sequence numbers for ordering  
o	Encryption      parameters and CEK identifiers  
o	Job      metadata and processing timestamps 
2.6.3 Digital Signing
•	 
•	Sign     manifest.json using Ed25519 private key stored in HashiCorp Vault PKI     engine 
•	Include     signing certificate with OCSP stapling for real-time revocation checking 
•	Implement     certificate auto-renewal (30-day validity) via TPM-based attestation 
•	Support     signature verification downstream with certificate chain validation
2.7 Job Finalization
•	 
•	Write     final manifest and wrapped CEK data to job directory 
•	Update     state.json to SUCCESS with completion timestamp 
•	Critical:     Release exclusive device lock to allow user access 
•	Archive     job data according to retention policies 
•	Generate     job completion notifications with summary statistics

 
 
3. Agent Flow: Secure File Presentation
3.1 Secure Execution Environment
3.1.1 Enclave-Based Architecture
•	 
•	Split     Architecture: Untrusted shim process + trusted enclave core 
•	Use     Open Enclave SDK for cross-platform enclave development 
•	Shim     handles I/O operations and user interface 
•	Enclave     performs all cryptographic operations and policy enforcement 
•	Implement     secure channel between shim and enclave for data transfer
3.1.2 Hardware Attestation
•	 
•	On     startup, generate TPM Quote for platform integrity measurement 
•	Obtain     MDM compliance token for device policy compliance verification 
•	Present     attestation evidence to HashiCorp Vault for authentication 
•	Implement     periodic re-attestation (configurable interval, default: 24 hours)
3.2 Key Management & Unwrapping
3.2.1 Vault Authentication
•	 
•	Use     TPM-bound AppRole authentication for initial service authentication 
•	Implement     short-lived token rotation (default: 1-hour TTL) 
•	N  Persistent Storage: Enforce -cache=false flag to prevent token caching 
•	Support     offline operation with limited cached policy decisions
3.2.2 Secure CEK Unwrapping
•	 
•	Mutual     ECDH Key Exchange: Establish ephemeral shared secret between agent     enclave and Vault 
•	Agent     requests CEK unwrap with job context: job_id, manifest_hash,     user_identity, timestamp 
•	Vault     returns CEK encrypted with ECDH-derived key 
•	Enclave-Only     Unwrapping: Perform final CEK decryption entirely within enclave     memory 
•	Immediately     discard wrapped CEK data after successful unwrap
3.2.3 User-Based Access Control (UBAC)
•	 
•	Issue     unwrap tokens scoped to user identity via Vault OIDC integration 
•	Agent     queries Active Directory LDAP for user group membership 
•	Cache     group membership with short TTL (default: 15 minutes) 
•	Enclave     verifies user claims against manifest access policies before unwrap
3.3 Controlled File Presentation
3.3.1 Windows Projected File System (ProjFS) Integration
•	 
•	Memory-Only     Decryption: Files remain encrypted at rest, decrypted on-demand in     memory 
•	Implement     ProjFS provider for seamless user experience 
•	Integrate     with Windows Data Loss Prevention (DLP) and Endpoint Detection &     Response (EDR) 
•	Restrict     memory paging for decrypted content to prevent disk-based recovery
3.3.2 File Access Controls
•	 
•	Enforce     read-only access by default with explicit write permissions 
•	Implement     file-level access controls based on user group membership 
•	Support     watermarking and classification labelling integration 
•	Log     all file access attempts with user identity and access patterns
3.4 Secure Write Operations
3.4.1 Write Intent Processing
•	 
•	Intercept     write operations through ProjFS write hooks 
•	Validate     write permissions against current user policy 
•	Generate     new CEK for modified content within enclave 
•	Re-encrypt     modified files with new CEK immediately
3.4.2 Policy Re-validation
•	 
•	Submit     modified content to OPA for policy compliance checking 
•	Abort     write operations on policy violations with detailed error messages 
•	Maintain     audit trail of all modification attempts and policy decisions
3.4.3 Two-Phase Commit Protocol
•	 
•	Staging     Phase: Store encrypted modifications in memory-based staging area 
•	Commit     Phase: Atomically write new manifest and encrypted blobs 
•	Implement     conflict detection via manifest version comparison 
•	Provide     user resolution interface for concurrent modification conflicts
3.5 Audit & Logging
3.5.1 Immutable Log Chain
•	 
•	Generate     hash-linked audit logs within enclave: prev_hash || entry_data → SHA-256 
•	Include     sequence numbers and cryptographic timestamps 
•	Write     tamper-evident logs to logs.jsonl with regular integrity verification
3.5.2 External Audit Integration
•	 
•	Push     log digests to ImmuDB or WORM storage for external tamper evidence 
•	Support     integration with SIEM systems (Splunk, ELK Stack, Azure Sentinel) 
•	Generate     compliance reports for regulatory requirements (GDPR, HIPAA, SOX)
3.5.3 Fail-Safe Behaviour
•	 
•	Fail-Closed     Policy: If Vault/OPA unreachable, deny all unwrap and write operations 
•	Maintain     clear error state indicators for users and administrators 
•	Implement     graceful degradation with cached policy decisions when appropriate

4. Key Management Infrastructure
4.1 HashiCorp Vault Configuration
4.1.1 Transit Engine (Cryptographic Operations)
•	 
•	HSM     Integration: Configure PKCS#11 integration with certified HSM (Luna     SA, nShield) 
•	Key     Hierarchy: Root KEK in HSM, derived KEKs for different security     domains 
•	Support     key rotation with backward compatibility for existing encrypted content 
•	Implement     key escrow capabilities for regulatory compliance requirements
4.1.2 PKI Engine (Certificate Management)
•	 
•	Issue     short-lived certificates (30-day validity) for gateway and agent signing 
•	Implement     automated certificate renewal via TPM-based attestation 
•	Support     certificate revocation with OCSP and CRL distribution 
•	Maintain     certificate transparency logging for audit requirements
4.1.3 Identity & Access Management
•	 
•	OIDC     Integration: Connect with enterprise identity providers (Azure AD,     Okta) 
•	AppRole     Authentication: For service-to-service authentication 
•	User-Based     Policies: Dynamic policy assignment based on user attributes 
•	Implement     just-in-time access provisioning for administrative operations
4.2 Open Policy Agent (OPA) Configuration
4.2.1 Policy Bundle Management
•	 
•	Implement     signed policy bundles with Ed25519 signature verification 
•	Support     GitOps-based policy deployment with version control 
•	Enforce     policy rollback protection to prevent downgrade attacks 
•	Maintain     policy decision audit logs with full request/response context
4.2.2 Decision Caching & Performance
•	 
•	Memory-Only     Caching: Sidecar cache permitted only in volatile memory 
•	Implement     policy decision memoization for repeated queries 
•	Fail-Closed     Behaviour: Deny operations on cache miss or policy engine     unavailability 
•	Support     policy simulation and testing modes for safe policy updates
4.3 Hardware Security Module (HSM) Integration
4.3.1 HSM Requirements
•	 
•	Certification:     FIPS 140-2 Level 3 or Common Criteria EAL4+ certified 
•	High     Availability: Clustered HSM deployment with automatic failover 
•	Key     Management: Support for key generation, wrapping, and secure key     storage 
•	Audit     Logging: Comprehensive HSM operation logging with tamper detection
4.3.2 Key Lifecycle Management
•	 
•	Automated     key generation with cryptographically secure entropy sources 
•	Key     backup and recovery procedures with split-knowledge controls 
•	Regular     key rotation schedules based on cryptographic best practices 
•	Secure     key destruction with certified media sanitization

5. Security & Compliance Framework
5.1 Threat Model & Mitigations
5.1.1 Insider Threats
•	 
•	Mitigation:     Privileged access management with just-in-time elevation 
•	Comprehensive     audit logging of all administrative actions 
•	Separation     of duties for critical operations 
•	Regular     access reviews and automated deprovisioning
5.1.2 Malware & Advanced Persistent Threats
•	 
•	Mitigation:     Multi-layered malware detection with static and dynamic analysis 
•	Application     whitelisting and code signing enforcement 
•	Network     segmentation with micro-segmentation policies 
•	Behavioural     analysis and anomaly detection
5.1.3 Cryptographic Attacks
•	 
•	Mitigation:     Use of established cryptographic algorithms (AES-256, Ed25519, SHA-256) 
•	Regular     cryptographic library updates and vulnerability management 
•	Quantum-resistant     algorithm evaluation and migration planning 
•	Hardware-based     key protection with HSM integration
5.2 Compliance Requirements
5.2.1 Data Protection Regulations
•	 
•	GDPR     Compliance: Data minimization, purpose limitation, and user consent     management 
•	CCPA     Compliance: Consumer rights management and data disclosure tracking 
•	HIPAA     Compliance: Administrative, physical, and technical safeguards for PHI
5.2.2 Industry Standards
•	 
•	NIST     Cybersecurity Framework: Implementation of Identify, Protect, Detect,     Respond, Recover 
•	IS  27001: Information security management system controls

6. Implementation Considerations
6.1 Development Requirements
6.1.1 Technology Stack
•	 
•	Gateway:     Windows Service (Python) 
•	Filter     Driver: Windows Filter Manager 
•	Agent:     Windows Service with ProjFS integration 
•	Enclave:     Open Enclave SDK with Intel SGX or ARM TrustZone support 
•	Database:     SQLite for local job storage, MsSQL for centralized logging
6.1.2 Testing Strategy
•	 
•	Unit     Testing: Comprehensive test coverage with mocking for external     dependencies 
•	Integration     Testing: End-to-end workflow testing with real USB devices 
•	Security     Testing: Penetration testing, fuzzing, and vulnerability assessment 
•	Performance     Testing: Load testing with concurrent USB operations 
•	Compatibility     Testing: Multi-platform and multi-device testing
6.1.3 Quality Assurance
•	 
•	Code     Reviews: Mandatory peer review for all security-critical code 
•	Static     Analysis: Automated SAST scanning with SonarQube or similar 
•	Dynamic     Analysis: Runtime security testing with tools like Veracode 
•	Dependency     Scanning: Regular scanning for vulnerable third-party libraries
6.2 Deployment Architecture
6.2.1 Enterprise Deployment
•	 
•	Group     Policy Integration: Automated deployment via Active Directory GPO 
•	Configuration     Management: Centralized configuration with Ansible/Puppet 
•	Update     Management: Automated updates with rollback capabilities 
•	Monitoring     Integration: Enterprise monitoring system integration
6.2.2 Cloud Integration
•	 
•	Hybrid     Architecture: Support for cloud-hosted Vault and OPA instances 
•	Multi-Region     Deployment: Geographic distribution for performance and resilience 
•	Disaster     Recovery: Cross-region backup and recovery capabilities 
•	Compliance:     Cloud security posture management and compliance monitoring
6.3 Performance & Scalability
6.3.1 Performance Requirements
•	 
•	USB     Processing: Complete processing within 2 minutes for typical 32GB     device 
•	File     Access: Sub-100ms latency for file access through ProjFS 
•	Concurrent     Operations: Support 10+ simultaneous USB device processing 
•	Memory     Usage: Maximum 512MB per gateway instance, 256MB per agent
6.3.2 Scalability Considerations
•	 
•	Horizontal     Scaling: Support multiple gateway instances per organization 
•	Load     Balancing: Distribute Vault and OPA requests across multiple instances 
•	Caching     Strategy: Intelligent caching to reduce backend load 
•	Resource     Management: Automatic resource cleanup and garbage collection

7. Risk Assessment & Mitigation
7.1 Technical Risks
7.1.1 Single Points of Failure
•	 
•	Risk:     Vault or HSM unavailability prevents all operations 
•	Mitigation:     High-availability clustering with automatic failover 
•	Contingency:     Offline emergency access procedures for critical situations
7.1.2 Performance Bottlenecks
•	 
•	Risk:     Large file processing causes system performance degradation 
•	Mitigation:     Streaming encryption, chunked processing, and resource throttling 
•	Monitoring:     Real-time performance metrics with automatic alerts
7.1.3 Compatibility Issues
•	 
•	Risk:     Filter driver incompatibility with security software 
•	Mitigation:     Extensive compatibility testing and whitelisting procedures 
•	Support:     Technical support processes for compatibility resolution
7.2 Security Risks
7.2.1 Key Compromise
•	 
•	Risk:     CEK or KEK compromise leads to data exposure 
•	Mitigation:     Hardware-based key protection, regular rotation, and compromise detection 
•	Response:     Automated key revocation and re-encryption procedures
7.2.2 Policy Bypass
•	 
•	Risk:     Users find ways to bypass security controls 
•	Mitigation:     Defence-in-depth architecture with multiple policy enforcement points 
•	Detection:     Behavioural analysis and anomaly detection for bypass attempts
7.3 Operational Risks
7.3.1 Administrative Errors
•	 
•	Risk:     Misconfiguration leads to security gaps or service outages 
•	Mitigation:     Configuration validation, change management processes, and rollback     capabilities 
•	Training:     Comprehensive administrator training and certification
7.3.2 Vendor Dependencies
•	 
•	Risk:     Third-party component vulnerabilities or discontinuation 
•	Mitigation:     Vendor security assessment, alternative vendor evaluation, and escape     planning 
•	Monitoring:     Continuous vulnerability monitoring and update management

 
8. Revocation Flow & Access Termination
8.1 Revocation Scenarios
8.1.1 Immediate Revocation Triggers
•	 
•	User     termination or role change 
•	Device     compromise or theft 
•	Policy     violation detection 
•	Certificate     expiration or revocation 
•	Administrative     security incident response
8.2 Technical Implementation
8.2.1 Short-Lived Token Strategy
•	 
•	CEK     Unwrap Tokens: Maximum TTL of 15 minutes (configurable: 5-30 minutes) 
•	AppRole     Tokens: Maximum TTL of 1 hour with automatic renewal 
•	Policy     Tokens: Maximum TTL of 2 hours with forced refresh on policy version     mismatch
8.2.2 Vault Lease Revocation
Revocation API Call:
POST /v1/sys/leases/revoke-prefix
{
  "lease_id": "auth/approle/login/<user_identifier>/*"
}
 
Response Processing:
- HTTP 200: Revocation successful
- HTTP 204: No active leases found
- HTTP 500: Partial revocation (requires retry)
8.2.3 Policy Version Enforcement
•	 
•	Version     Bump: Increment global policy version number 
•	Agent     Validation: Agents verify policy version on each unwrap request 
•	Forced     Re-wrap: Version mismatch triggers complete session termination and     re-authentication
 
 
8.3 Revocation Verification
8.3.1 Immediate Effects (< 30 seconds)
•	 
•	Active     Agent sessions terminated 
•	In-memory     CEKs cleared from all endpoints 
•	New     authentication attempts denied
8.3.2 Propagation Timeline
•	 
•	Vault     revocation: Immediate (< 5 seconds) 
•	OPA     policy distribution: Within 1 minute 
•	Agent     policy refresh: Within 2 minutes 
•	Full     system consistency: Within 5 minutes

Phase 1 – MVP
Gateway Service
USB device detection & exclusive volume locking
Metadata collection
File enumeration + sanitization (normalize paths, drop dangerous ADS, etc.)
Malware scanning (Defender + ClamAV basic integration)
CEK generation + AES-256 encryption
Manifest creation (hashes, metadata)
Digital signing via Vault
Agent Service
Basic attestation (TPM Quote at start up)
Vault authentication (AppRole + short-lived tokens)
Secure CEK unwrap in enclave (SGX or VBS fallback)
Read-only file access via ProjFS (decrypted in memory only)
Key Management
Vault Transit for CEK wrapping
Vault PKI for manifest signing
Phase 2 – Security Hardening 
Gateway
OPA integration (policy bundles, signed & versioned)
Policy enforcement (file size, count, blacklist/whitelist, archive depth, etc.
Quarantine flow for malware/policy violations
Advanced malware analysis pipeline (sandbox in VM)
Agent
UBAC enforcement (AD group membership checks)
Secure write operations (new CEKs for modifications, policy re-validation)
KMS
Automatic key rotation strategy
Phase 3 – Revocation
Revocation Flow
Immediate revocation (AppRole/token invalidation, deny list, policy version bump)
Agent cache invalidation + forced re-authentication
Offline Mode
Grace periods (read-only cached policy, 2 hours default)
Fail-closed enforcement after expiry
Fallback Enclave Architecture 
Runtime detection of SGX/TrustZone/VBS 

