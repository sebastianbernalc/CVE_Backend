-- Tabla cve_data
CREATE TABLE cve_data (
    id VARCHAR(50) PRIMARY KEY,
    sourceIdentifier VARCHAR(255),
    published DATETIME,
    lastModified DATETIME,
    vulnStatus VARCHAR(50),
    description_en TEXT,
    description_es TEXT,
    vendor VARCHAR(255)
);

-- Tabla cvss_metrics_v31
CREATE TABLE cvss_metrics_v31 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50),
    version VARCHAR(10),
    vectorString TEXT,
    attackVector VARCHAR(50),
    attackComplexity VARCHAR(50),
    privilegesRequired VARCHAR(50),
    userInteraction VARCHAR(50),
    scope VARCHAR(50),
    confidentialityImpact VARCHAR(50),
    integrityImpact VARCHAR(50),
    availabilityImpact VARCHAR(50),
    baseScore FLOAT,
    baseSeverity VARCHAR(50),
    exploitabilityScore FLOAT,
    impactScore FLOAT,
    FOREIGN KEY (cve_id) REFERENCES cve_data(id)
);

-- Tabla cvss_metrics_v2
CREATE TABLE cvss_metrics_v2 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50),
    version VARCHAR(10),
    vectorString TEXT,
    accessVector VARCHAR(50),
    accessComplexity VARCHAR(50),
    authentication VARCHAR(50),
    confidentialityImpact VARCHAR(50),
    integrityImpact VARCHAR(50),
    availabilityImpact VARCHAR(50),
    baseScore FLOAT,
    baseSeverity VARCHAR(50),
    exploitabilityScore FLOAT,
    impactScore FLOAT,
    acInsufInfo BOOLEAN,
    obtainAllPrivilege BOOLEAN,
    obtainUserPrivilege BOOLEAN,
    obtainOtherPrivilege BOOLEAN,
    userInteractionRequired BOOLEAN,
    FOREIGN KEY (cve_id) REFERENCES cve_data(id)
);

-- Tabla cwe
CREATE TABLE cwe (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50),
    cwe_id VARCHAR(50),
    FOREIGN KEY (cve_id) REFERENCES cve_data(id)
);

-- Tabla references
CREATE TABLE referencess (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(50),
    url TEXT,
    source VARCHAR(255),
    tags TEXT,
    FOREIGN KEY (cve_id) REFERENCES cve_data(id)
);
