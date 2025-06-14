# CVE Research Toolkit - TODO List

## Phase 1: Core Infrastructure & Reliability (High Priority)

- [x] Modularize the codebase into separate packages for models, connectors, core engine, and reporting
- [x] Implement proper error handling with custom exceptions and retry logic
- [ ] Add performance optimization with connection pooling and batch processing (no caching - workstation based)
- [ ] Enhance type safety with Pydantic models and proper type hints
- [ ] Add comprehensive testing with fixtures and mocks
- [ ] Improve security with input validation and rate limiting

## Phase 2: Enhanced OSINT & Research Capabilities (High Priority)

- [ ] Design evidence-based mechanical analysis framework for exploitation prerequisites
- [ ] Build environmental condition extraction system (OS requirements, configuration dependencies, etc.)
- [ ] Integrate CVEfixes repository for before/after code analysis
- [ ] Create local web UI wrapper for interactive data consumption and analysis
- [ ] Add CVE cross-referencing functionality in Excel output (core feature)

## Phase 3: Second Tier Data Layers & Control Mapping (Medium Priority)

- [ ] Implement CWE-based control framing system to map weakness categories to control families
- [ ] Implement CVE2CAPEC integration for systematic CVE→CWE→CAPEC→ATT&CK mapping
- [ ] Implement MITRE framework integration (CWE, CAPEC, ATT&CK) for systematic analysis
- [ ] Redesign compensating controls automation using evidence-based matching
- [ ] Enhance Excel/Word output with technical deep-dive sections and templated analysis frameworks (future)

## Phase 4: Advanced Research Features (Medium Priority)

- [ ] Create plugin architecture for easy extension with new data sources
- [ ] Implement monitoring with metrics and health checks
- [ ] Enhance documentation with better docstrings and examples

## Experimental/Research Items (Low Priority)

- [ ] Explore CVE cross-referencing within batches (experimental branch)
- [ ] Research vulnerability analysis frameworks for systematic prerequisite extraction

## Completed Tasks

- [x] Analyze code structure and organization
- [x] Review error handling and logging patterns
- [x] Evaluate performance bottlenecks
- [x] Assess type safety and data validation
- [x] Review API design and extensibility
- [x] Document improvement recommendations
- [x] Analyze UX, architecture, and business value opportunities
- [x] Clarify project scope and purpose (OSINT research tool, not vulnerability management platform)
- [x] Research all existing data source organizations for additional OSINT opportunities
- [x] Design Second Tier Data Layers architecture for CVE-to-control mapping
- [x] Validate CWE-based control framing approach
- [x] Determine strategic implementation sequence (modularization → data sources → UI)
- [x] Recovered .gitignore file and cleaned up project junk files

## Recent Completion: Empty Column Resolution (2025-06-14)

### Phase 1: CWE Extraction and Reference Categorization
- [x] Enhanced CVE Project connector to extract CWE data from problemTypes in CVE JSON format
- [x] Added reference categorization to identify patches, vendor advisories, mitigations, and fix versions
- [x] Updated data enrichment logic to populate CWE data from foundational source when MITRE data unavailable
- [x] Fixed EPSS percentile assignment in threat data enrichment
- [x] Populated vendor_advisories and patches fields from categorized CVE Project references

### Phase 2: MITRE Framework Integration
- [x] Implemented CWE-to-CAPEC-to-ATT&CK mapping in MITRE connector for systematic framework integration
- [x] Enhanced research engine to process data layers in order and pass CWE data to MITRE connector
- [x] Populated CAPEC IDs, Attack Techniques, and Attack Tactics fields in CSV output

### Changes Made:
1. **CWE Extraction**: Modified CVEProjectConnector.parse() to extract CWE IDs and descriptions from both CNA and ADP problemTypes
2. **Reference Categorization**: Enhanced reference parsing to categorize URLs into patches, vendor advisories, mitigations, and fix versions based on tags and URL patterns
3. **MITRE Framework Mapping**: Implemented comprehensive CWE→CAPEC→ATT&CK mapping tables in MITREConnector.parse() covering 17 common vulnerability types
4. **Data Flow Enhancement**: Modified VulnerabilityResearchEngine to:
   - Process data layers in dependency order (foundational first)
   - Pass extracted CWE data to MITRE connector for systematic mapping
   - Populate all weakness tactics fields (CAPEC IDs, attack techniques, attack tactics)
   - Include EPSS percentile in threat data assignment
5. **Testing**: Verified functionality with comprehensive test suite and targeted MITRE mapping tests

### Result:
All previously empty CSV columns are now populated:
- **CWE**: Extracted from CVE JSON problemTypes 
- **CAPEC IDs**: Mapped from CWE using systematic vulnerability patterns
- **Attack Techniques**: Mapped from CAPEC to ATT&CK techniques (T-codes)
- **Attack Tactics**: Mapped from CAPEC to ATT&CK tactics (TA-codes)
- **EPSS Percentile**: Fixed data flow from threat context connectors
- **Vendor Advisories**: Categorized from CVE Project references
- **Patches**: Categorized from CVE Project references