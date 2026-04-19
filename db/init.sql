CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL UNIQUE,
    vendor_release_date DATE,
    vendor_release_url TEXT NOT NULL,
    cve_url TEXT NOT NULL,
    published_date TIMESTAMPTZ,
    updated_date TIMESTAMPTZ,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cvss_metrics (
    id BIGSERIAL PRIMARY KEY,
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    score NUMERIC(4,1),
    vector TEXT NOT NULL,
    severity TEXT NOT NULL,
    UNIQUE (vulnerability_id, version, vector)
);

CREATE TABLE IF NOT EXISTS cpes (
    id BIGSERIAL PRIMARY KEY,
    cpe TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS vulnerability_cpes (
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cpe_id BIGINT NOT NULL REFERENCES cpes(id) ON DELETE CASCADE,
    PRIMARY KEY (vulnerability_id, cpe_id)
);

CREATE TABLE IF NOT EXISTS cwes (
    id BIGSERIAL PRIMARY KEY,
    cwe_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_cwes (
    vulnerability_id BIGINT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cwe_ref_id BIGINT NOT NULL REFERENCES cwes(id) ON DELETE CASCADE,
    PRIMARY KEY (vulnerability_id, cwe_ref_id)
);
