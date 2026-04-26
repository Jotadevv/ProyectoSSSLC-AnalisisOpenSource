import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from "react";
import "./home.css";

type Severity = "critical" | "high" | "moderate" | "low" | "info" | "unknown";
type SeverityFilter = Severity | "all";

type Vulnerability = {
  id?: string;
  name?: string;
  package?: string;
  version?: string;
  severity?: string;
  fix_versions?: string;
  fixed_in?: string;
  fix_available?: boolean;
  description?: string;
  url?: string;
  intel?: VulnerabilityIntel;
};

type VulnerabilityIntel = {
  primary_id?: string;
  detected_type?: string;
  catalog_coverage?: number;
  catalog_total?: number;
  intel_score?: number;
  intel_risk_level?: string;
  references?: VulnerabilityReference[];
  signals?: {
    cisa_kev?: { listed?: boolean };
    first_epss?: { score?: number | null };
  };
};

type AuditSummary = {
  total_vulnerabilities: number;
  dependencies_scanned: number;
  fix_available: number;
  by_severity: Record<Severity, number>;
  global_risk_level: string;
  global_risk_score: number;
};

type Recommendation = {
  package: string;
  severity: string;
  priority: number;
  suggested_version: string | null;
  update_command: string;
  remediation_order: number;
  vulnerability_count: number;
};

type AuditResponse = {
  ecosystem: string;
  scanned_at: string;
  duration_ms: number;
  summary: AuditSummary;
  intelligence_summary?: IntelligenceSummary;
  vulnerabilities: Vulnerability[];
  recommendations: Recommendation[];
  cached?: boolean;
};

type VulnerabilityDatabase = {
  id: string;
  name: string;
  description: string;
};

type VulnerabilityReference = {
  database_id: string;
  database_name: string;
  url: string;
};

type VulnerabilityIntelResponse = {
  query: string;
  detected_type: string;
  total_sources: number;
  references: VulnerabilityReference[];
};

type IntelligenceSummary = {
  catalog_sources_total: number;
  vulnerabilities_enriched: number;
  full_catalog_matches: number;
  coverage_percent: number;
  detected_ids: {
    cve: number;
    ghsa: number;
    pysec: number;
    generic: number;
  };
  known_exploited_count: number;
  average_epss: number | null;
  highest_epss: { id: string; score: number } | null;
  top_intel_score: { id: string; score: number } | null;
};

const severityOrder: Severity[] = [
  "critical",
  "high",
  "moderate",
  "low",
  "info",
  "unknown",
];

const severityLabels: Record<Severity, string> = {
  critical: "Critica",
  high: "Alta",
  moderate: "Moderada",
  low: "Baja",
  info: "Info",
  unknown: "Sin dato",
};

const severityColors: Record<Severity, string> = {
  critical: "#d73f3f",
  high: "#ef7f2d",
  moderate: "#f4b942",
  low: "#35b6a9",
  info: "#4f8ad9",
  unknown: "#72829f",
};

const CVE_REGEX = /CVE-\d{4}-\d{4,}/i;
const GHSA_REGEX = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i;
const PYSEC_REGEX = /PYSEC-\d{4}-\d+/i;
const LOADING_STEPS = [
  "Validando el formato del archivo de dependencias...",
  "Ejecutando motores de auditoria y recoleccion de hallazgos...",
  "Normalizando severidades y consolidando vulnerabilidades...",
  "Construyendo graficas y resumen ejecutivo del riesgo...",
];

function normalizeSeverity(value: string | undefined): Severity {
  if (!value) return "unknown";

  const normalized = value.trim().toLowerCase();
  if (normalized === "medium") return "moderate";
  if (severityOrder.includes(normalized as Severity)) {
    return normalized as Severity;
  }

  return "unknown";
}

function emptySeverityMap(): Record<Severity, number> {
  return {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    info: 0,
    unknown: 0,
  };
}

function buildFallbackSummary(vulnerabilities: Vulnerability[]): AuditSummary {
  const bySeverity = emptySeverityMap();
  let fixAvailable = 0;

  vulnerabilities.forEach((vulnerability) => {
    const severity = normalizeSeverity(vulnerability.severity);
    bySeverity[severity] += 1;

    if (vulnerability.fix_available || vulnerability.fixed_in) {
      const fixedIn = vulnerability.fixed_in?.toLowerCase() || "";
      if (fixedIn && fixedIn !== "no disponible") {
        fixAvailable += 1;
      } else if (vulnerability.fix_available) {
        fixAvailable += 1;
      }
    }
  });

  const total = vulnerabilities.length;
  let global_risk_level = "Sin riesgo";
  let global_risk_score = 0;
  if (total > 0) {
    const score = (
      bySeverity.critical * 5 +
      bySeverity.high * 4 +
      bySeverity.moderate * 3 +
      bySeverity.low * 2 +
      bySeverity.info * 1 +
      bySeverity.unknown * 0
    ) / total;
    global_risk_score = Math.round(score * 100) / 100;
    if (score < 1.5) global_risk_level = "Bajo";
    else if (score < 2.5) global_risk_level = "Medio";
    else if (score < 3.5) global_risk_level = "Alto";
    else global_risk_level = "Crítico";
  }

  return {
    total_vulnerabilities: total,
    dependencies_scanned: 0,
    fix_available: fixAvailable,
    by_severity: bySeverity,
    global_risk_level,
    global_risk_score,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parseIntelligenceSummary(value: unknown): IntelligenceSummary | undefined {
  if (!isRecord(value)) return undefined;

  const detected = isRecord(value.detected_ids) ? value.detected_ids : {};
  const highestEpss = isRecord(value.highest_epss) ? value.highest_epss : null;
  const topIntel = isRecord(value.top_intel_score) ? value.top_intel_score : null;

  return {
    catalog_sources_total:
      typeof value.catalog_sources_total === "number" ? value.catalog_sources_total : 0,
    vulnerabilities_enriched:
      typeof value.vulnerabilities_enriched === "number" ? value.vulnerabilities_enriched : 0,
    full_catalog_matches:
      typeof value.full_catalog_matches === "number" ? value.full_catalog_matches : 0,
    coverage_percent: typeof value.coverage_percent === "number" ? value.coverage_percent : 0,
    detected_ids: {
      cve: typeof detected.cve === "number" ? detected.cve : 0,
      ghsa: typeof detected.ghsa === "number" ? detected.ghsa : 0,
      pysec: typeof detected.pysec === "number" ? detected.pysec : 0,
      generic: typeof detected.generic === "number" ? detected.generic : 0,
    },
    known_exploited_count:
      typeof value.known_exploited_count === "number" ? value.known_exploited_count : 0,
    average_epss: typeof value.average_epss === "number" ? value.average_epss : null,
    highest_epss:
      highestEpss &&
      typeof highestEpss.id === "string" &&
      typeof highestEpss.score === "number"
        ? { id: highestEpss.id, score: highestEpss.score }
        : null,
    top_intel_score:
      topIntel &&
      typeof topIntel.id === "string" &&
      typeof topIntel.score === "number"
        ? { id: topIntel.id, score: topIntel.score }
        : null,
  };
}

function parseApiResponse(payload: unknown): AuditResponse | null {
  if (Array.isArray(payload)) {
    return {
      ecosystem: "unknown",
      scanned_at: new Date().toISOString(),
      duration_ms: 0,
      summary: buildFallbackSummary(payload as Vulnerability[]),
      vulnerabilities: payload as Vulnerability[],
      recommendations: [],
      cached: false,
    };
  }

  if (!isRecord(payload)) return null;
  if (!Array.isArray(payload.vulnerabilities)) return null;

  const vulnerabilities = payload.vulnerabilities as Vulnerability[];
  const rawSummary = isRecord(payload.summary) ? payload.summary : {};
  const intelligenceSummary =
    parseIntelligenceSummary(payload.intelligence_summary) ||
    parseIntelligenceSummary(rawSummary.intelligence);
  const severityMap = emptySeverityMap();

  severityOrder.forEach((severity) => {
    const value = rawSummary.by_severity;
    if (isRecord(value) && typeof value[severity] === "number") {
      severityMap[severity] = value[severity] as number;
    }
  });

  return {
    ecosystem: typeof payload.ecosystem === "string" ? payload.ecosystem : "unknown",
    scanned_at: typeof payload.scanned_at === "string" ? payload.scanned_at : new Date().toISOString(),
    duration_ms: typeof payload.duration_ms === "number" ? payload.duration_ms : 0,
    summary: {
      total_vulnerabilities:
        typeof rawSummary.total_vulnerabilities === "number"
          ? rawSummary.total_vulnerabilities
          : vulnerabilities.length,
      dependencies_scanned:
        typeof rawSummary.dependencies_scanned === "number"
          ? rawSummary.dependencies_scanned
          : 0,
      fix_available:
        typeof rawSummary.fix_available === "number" ? rawSummary.fix_available : 0,
      by_severity: severityMap,
      global_risk_level:
        typeof rawSummary.global_risk_level === "string" ? rawSummary.global_risk_level : "Sin riesgo",
      global_risk_score:
        typeof rawSummary.global_risk_score === "number" ? rawSummary.global_risk_score : 0,
    },
    intelligence_summary: intelligenceSummary,
    vulnerabilities,
    recommendations: Array.isArray(payload.recommendations) ? payload.recommendations as Recommendation[] : [],
    cached: typeof payload.cached === "boolean" ? payload.cached : false,
  };
}

function formatDate(dateIso: string): string {
  const date = new Date(dateIso);
  if (Number.isNaN(date.getTime())) return "N/A";

  return date.toLocaleString("es-CO", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function buildDonutGradient(bySeverity: Record<Severity, number>, total: number): string {
  if (total <= 0) {
    return "conic-gradient(#1f2c39 0deg 360deg)";
  }

  let currentAngle = 0;
  const segments: string[] = [];

  severityOrder.forEach((severity) => {
    const count = bySeverity[severity];
    if (count <= 0) return;

    const segmentAngle = (count / total) * 360;
    const nextAngle = currentAngle + segmentAngle;
    segments.push(`${severityColors[severity]} ${currentAngle}deg ${nextAngle}deg`);
    currentAngle = nextAngle;
  });

  if (segments.length === 0) {
    return "conic-gradient(#1f2c39 0deg 360deg)";
  }

  return `conic-gradient(${segments.join(", ")})`;
}

function detectVulnerabilityIdType(value: string): string {
  const normalized = value.trim().toUpperCase();
  if (CVE_REGEX.test(normalized)) return "CVE";
  if (GHSA_REGEX.test(normalized)) return "GHSA";
  if (PYSEC_REGEX.test(normalized)) return "PYSEC";
  return "GENERIC";
}

function extractVulnerabilityQuery(vulnerability: Vulnerability): string {
  const fields = [
    vulnerability.id,
    vulnerability.name,
    vulnerability.description,
  ]
    .filter(Boolean)
    .map((item) => String(item));

  for (const field of fields) {
    const cveMatch = field.match(CVE_REGEX);
    if (cveMatch?.[0]) return cveMatch[0].toUpperCase();

    const ghsaMatch = field.match(GHSA_REGEX);
    if (ghsaMatch?.[0]) return ghsaMatch[0].toUpperCase();

    const pysecMatch = field.match(PYSEC_REGEX);
    if (pysecMatch?.[0]) return pysecMatch[0].toUpperCase();
  }

  const fallback = vulnerability.id || vulnerability.name || vulnerability.package || "";
  return String(fallback).trim();
}

function Home() {
  const [fileName, setFileName] = useState<string>("");
  const [audit, setAudit] = useState<AuditResponse | null>(null);
  const [rawResults, setRawResults] = useState<unknown>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedDescriptions, setExpandedDescriptions] = useState<Set<string>>(new Set());
  const [intelQuery, setIntelQuery] = useState("");
  const [intelLoading, setIntelLoading] = useState(false);
  const [intelError, setIntelError] = useState<string | null>(null);
  const [intelResult, setIntelResult] = useState<VulnerabilityIntelResponse | null>(null);
  const [vulnerabilityDatabases, setVulnerabilityDatabases] = useState<VulnerabilityDatabase[]>([]);
  const [loadingStepIndex, setLoadingStepIndex] = useState(0);
  const [loadingProgress, setLoadingProgress] = useState(8);

  useEffect(() => {
    const loadDatabases = async () => {
      try {
        const response = await fetch("/api/vulnerability-databases");
        if (!response.ok) return;

        const payload = (await response.json()) as { databases?: VulnerabilityDatabase[] };
        if (Array.isArray(payload.databases)) {
          setVulnerabilityDatabases(payload.databases);
        }
      } catch (loadError) {
        console.error("No se pudo cargar el catalogo de bases", loadError);
      }
    };

    void loadDatabases();
  }, []);

  const bySeverity = useMemo(() => {
    if (!audit) return emptySeverityMap();
    return audit.summary.by_severity;
  }, [audit]);

  const donutGradient = useMemo(() => {
    const total = audit?.summary.total_vulnerabilities ?? 0;
    return buildDonutGradient(bySeverity, total);
  }, [audit, bySeverity]);

  const filteredVulnerabilities = useMemo(() => {
    if (!audit) return [];

    return audit.vulnerabilities.filter((vulnerability) => {
      const severity = normalizeSeverity(vulnerability.severity);
      const byFilter = severityFilter === "all" || severityFilter === severity;

      const haystack = [
        vulnerability.name,
        vulnerability.package,
        vulnerability.id,
        vulnerability.description,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      const bySearch = !searchTerm || haystack.includes(searchTerm.toLowerCase());
      return byFilter && bySearch;
    });
  }, [audit, searchTerm, severityFilter]);

  const topPackages = useMemo(() => {
    if (!audit) return [] as Array<{ pkg: string; count: number }>;

    const counts = new Map<string, number>();
    audit.vulnerabilities.forEach((item) => {
      const pkg = item.package || "unknown";
      counts.set(pkg, (counts.get(pkg) || 0) + 1);
    });

    return Array.from(counts.entries())
      .map(([pkg, count]) => ({ pkg, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [audit]);

  const intelSummary = useMemo(() => audit?.intelligence_summary, [audit]);

  const intelTypeLabel = useMemo(() => {
    if (!intelResult) return "N/A";
    if (intelResult.detected_type === "CVE") return "CVE";
    if (intelResult.detected_type === "GHSA") return "GHSA";
    if (intelResult.detected_type === "PYSEC") return "PYSEC";
    return "Busqueda general";
  }, [intelResult]);

  useEffect(() => {
    if (!loading) {
      setLoadingStepIndex(0);
      setLoadingProgress(8);
      return;
    }

    const stepTimer = window.setInterval(() => {
      setLoadingStepIndex((prev) => (prev + 1) % LOADING_STEPS.length);
    }, 1900);

    const progressTimer = window.setInterval(() => {
      setLoadingProgress((prev) => Math.min(prev + Math.random() * 9 + 2, 92));
    }, 520);

    return () => {
      window.clearInterval(stepTimer);
      window.clearInterval(progressTimer);
    };
  }, [loading]);

  const fetchVulnerabilityReferences = async (rawQuery: string) => {
    const normalized = rawQuery.trim();
    if (!normalized) {
      setIntelError("Ingresa un ID de vulnerabilidad para consultar fuentes.");
      return;
    }

    setIntelLoading(true);
    setIntelError(null);
    setIntelResult(null);

    try {
      const response = await fetch(
        `/api/vulnerability/${encodeURIComponent(normalized)}/references`,
      );
      const payload = (await response.json()) as VulnerabilityIntelResponse & { error?: string };

      if (!response.ok) {
        setIntelError(payload.error || "No se pudo consultar las bases de datos.");
        return;
      }

      setIntelResult(payload);
      setIntelQuery(payload.query || normalized);
    } catch (requestError) {
      console.error(requestError);
      setIntelError("No se pudo conectar con el servicio de fuentes externas.");
    } finally {
      setIntelLoading(false);
    }
  };

  const handleIntelSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    await fetchVulnerabilityReferences(intelQuery);
  };

  const handleFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0] || null;
    if (!selectedFile) return;

    if (selectedFile.name !== "requirements.txt" && selectedFile.name !== "package.json") {
      setError("Solo se permiten requirements.txt o package.json");
      return;
    }

    setFileName(selectedFile.name);
    setLoading(true);
    setLoadingStepIndex(0);
    setLoadingProgress(10);
    setError(null);
    setAudit(null);
    setRawResults(null);
    setShowRaw(false);
    setSearchTerm("");
    setSeverityFilter("all");
    setExpandedDescriptions(new Set());
    setIntelError(null);
    setIntelResult(null);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const endpoint = selectedFile.name === "requirements.txt" ? "/audit/python" : "/audit/npm";
      const response = await fetch(endpoint, { method: "POST", body: formData });
      const payload = (await response.json()) as unknown;

      if (!response.ok) {
        const message = isRecord(payload) && typeof payload.error === "string"
          ? payload.error
          : "Error ejecutando auditoria";
        setError(message);
        return;
      }

      const parsed = parseApiResponse(payload);
      if (!parsed) {
        setError("La API devolvio un formato inesperado");
        return;
      }

      setAudit(parsed);
      const suggestedQuery = parsed.vulnerabilities
        .map((item) => extractVulnerabilityQuery(item))
        .find((candidate) => candidate.length > 0);
      if (suggestedQuery) {
        setIntelQuery(suggestedQuery);
      }

      if (selectedFile.name === "requirements.txt") {
        try {
          const rawResponse = await fetch("/audit/python_output");
          if (rawResponse.ok) {
            const rawPayload = (await rawResponse.json()) as unknown;
            setRawResults(rawPayload);
          }
        } catch (rawError) {
          console.error("No se pudo cargar el resultado crudo", rawError);
        }
      }
    } catch (requestError) {
      console.error(requestError);
      setError("No se pudo conectar con el backend de auditoria");
    } finally {
      setLoading(false);
      event.target.value = "";
    }
  };

  return (
    <div className="page-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      {loading && (
        <div className="loading-overlay" role="status" aria-live="polite" aria-atomic="true">
          <div className="loading-panel">
            <div className="loading-orbit" aria-hidden="true">
              <span />
              <span />
              <span />
            </div>
            <p className="loading-kicker">Escaneando {fileName || "dependencias"}</p>
            <h2>Creando reporte inteligente</h2>
            <p className="loading-step">{LOADING_STEPS[loadingStepIndex]}</p>
            <div className="loading-progress-track">
              <div
                className="loading-progress-fill"
                style={{ width: `${Math.round(loadingProgress)}%` }}
              />
            </div>
            <div className="loading-progress-meta">
              <span>{Math.round(loadingProgress)}%</span>
              <span>Este proceso puede tardar algunos segundos</span>
            </div>
          </div>
        </div>
      )}

      <header className="hero">
        <p className="hero-kicker">Secure Dependency Observatory</p>
        <h1>Analizador inteligente de vulnerabilidades</h1>
        <p>
          Carga tu archivo de dependencias y obtendras un panel visual con riesgo por severidad,
          paquetes afectados y estado de remediacion.
        </p>
      </header>

      <main className="content-grid">
        <section className="card upload-card">
          <div className="upload-top">
            <label
              htmlFor="audit-file"
              className={`upload-button${loading ? " disabled" : ""}`}
            >
              Seleccionar archivo
            </label>
            <input
              id="audit-file"
              type="file"
              className="hidden-input"
              accept=".txt,.json"
              disabled={loading}
              onChange={handleFileChange}
            />
            <span className="file-pill">{fileName || "Sin archivo"}</span>
          </div>

          <p className="help-text">Formatos permitidos: requirements.txt o package.json</p>

          {loading && (
            <div className="state-banner info">
              <span className="dot" />
              Ejecutando auditoria y construyendo reporte visual...
            </div>
          )}

          {error && <div className="state-banner error">{error}</div>}

          {audit && !error && (
            <div className="state-banner success">
              Auditoria completada para <strong>{audit.ecosystem.toUpperCase()}</strong> el{" "}
              {formatDate(audit.scanned_at)}
              {audit.cached ? " (resultado en cache)" : ""}
            </div>
          )}
        </section>

        {audit && !error && (
          <>
            <section className="metric-grid">
              <article className="card metric-card">
                <p>Vulnerabilidades</p>
                <h2>{audit.summary.total_vulnerabilities}</h2>
              </article>

              <article className="card metric-card">
                <p>Dependencias analizadas</p>
                <h2>{audit.summary.dependencies_scanned}</h2>
              </article>

              <article className="card metric-card">
                <p>Con fix disponible</p>
                <h2>{audit.summary.fix_available}</h2>
              </article>

              <article className="card metric-card">
                <p>Nivel de riesgo global</p>
                <h2 style={{ color: audit.summary.global_risk_level === 'Crítico' ? '#d73f3f' : 
                             audit.summary.global_risk_level === 'Alto' ? '#ef7f2d' : 
                             audit.summary.global_risk_level === 'Medio' ? '#f4b942' : '#35b6a9' }}>
                  {audit.summary.global_risk_level}
                </h2>
              </article>

              <article className="card metric-card">
                <p>Tiempo de analisis</p>
                <h2>{(audit.duration_ms / 1000).toFixed(2)}s</h2>
              </article>

              {intelSummary && (
                <>
                  <article className="card metric-card">
                    <p>Cobertura del catalogo</p>
                    <h2>{intelSummary.coverage_percent.toFixed(1)}%</h2>
                  </article>

                  <article className="card metric-card">
                    <p>En CISA KEV</p>
                    <h2>{intelSummary.known_exploited_count}</h2>
                  </article>

                  <article className="card metric-card">
                    <p>EPSS promedio</p>
                    <h2>
                      {intelSummary.average_epss !== null
                        ? intelSummary.average_epss.toFixed(3)
                        : "N/A"}
                    </h2>
                  </article>
                </>
              )}
            </section>

            <section className="chart-grid">
              <article className="card donut-card">
                <h3>Distribucion por severidad</h3>
                <div className="donut-wrap">
                  <div className="donut" style={{ backgroundImage: donutGradient }}>
                    <div className="donut-center">{audit.summary.total_vulnerabilities}</div>
                  </div>
                  <div className="legend">
                    {severityOrder.map((severity) => (
                      <div key={severity} className="legend-row">
                        <span
                          className="legend-color"
                          style={{ backgroundColor: severityColors[severity] }}
                        />
                        <span>{severityLabels[severity]}</span>
                        <strong>{bySeverity[severity]}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              </article>

              <article className="card bars-card">
                <h3>Top paquetes comprometidos</h3>
                {topPackages.length === 0 ? (
                  <p className="empty-hint">Sin paquetes vulnerables.</p>
                ) : (
                  <div className="bar-list">
                    {topPackages.map((item) => {
                      const percentage =
                        audit.summary.total_vulnerabilities > 0
                          ? (item.count / audit.summary.total_vulnerabilities) * 100
                          : 0;

                      return (
                        <div className="bar-row" key={item.pkg}>
                          <div className="bar-header">
                            <span>{item.pkg}</span>
                            <strong>{item.count}</strong>
                          </div>
                          <div className="bar-track">
                            <div className="bar-fill" style={{ width: `${Math.max(percentage, 6)}%` }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </article>
            </section>

            {audit.recommendations && audit.recommendations.length > 0 && (
              <section className="card recommendations-card">
                <h3>Motor de recomendaciones</h3>
                <div className="recommendations-list">
                  {audit.recommendations.map((rec) => (
                    <article className="rec-card" key={rec.package}>
                      <div className="rec-top">
                        <div>
                          <h4>{rec.package}</h4>
                          <p className="rec-meta">
                            Prioridad: {rec.priority} | Orden: {rec.remediation_order} | 
                            Vulnerabilidades: {rec.vulnerability_count}
                          </p>
                        </div>
                        <span
                          className="severity-badge"
                          style={{ backgroundColor: `${severityColors[rec.severity as Severity]}22`, 
                                   color: severityColors[rec.severity as Severity] }}
                        >
                          {severityLabels[rec.severity as Severity]}
                        </span>
                      </div>
                      <div className="rec-details">
                        {rec.suggested_version && (
                          <p><strong>Versión sugerida:</strong> {rec.suggested_version}</p>
                        )}
                        <p><strong>Comando de actualización:</strong></p>
                        <code className="rec-command">{rec.update_command}</code>
                      </div>
                    </article>
                  ))}
                </div>
              </section>
            )}

            <section className="card intel-card">
              <h3>Fuentes externas de vulnerabilidades</h3>
              <p className="intel-subtitle">
                Consulta CVE, GHSA o PYSEC para abrir multiples bases en un solo lugar.
              </p>

              <form className="intel-toolbar" onSubmit={handleIntelSubmit}>
                <input
                  value={intelQuery}
                  onChange={(event) => setIntelQuery(event.target.value)}
                  className="search-input"
                  placeholder="Ejemplo: CVE-2024-3094 o GHSA-xxxx-xxxx-xxxx"
                />
                <button type="submit" className="ghost-button" disabled={intelLoading}>
                  {intelLoading ? "Consultando..." : "Buscar fuentes"}
                </button>
              </form>

              {intelError && <div className="state-banner error">{intelError}</div>}

              {intelResult && !intelError && (
                <div className="intel-kpis">
                  <span>
                    Tipo detectado: <strong>{intelTypeLabel}</strong>
                  </span>
                  <span>
                    Consulta: <strong>{intelResult.query}</strong>
                  </span>
                  <span>
                    Fuentes: <strong>{intelResult.total_sources}</strong>
                  </span>
                </div>
              )}

              <div className="intel-db-grid">
                {vulnerabilityDatabases.map((database) => (
                  <article key={database.id} className="intel-db-chip">
                    <h4>{database.name}</h4>
                    <p>{database.description}</p>
                  </article>
                ))}
              </div>

              {intelResult && intelResult.references.length > 0 && (
                <div className="intel-ref-grid">
                  {intelResult.references.map((reference) => (
                    <article
                      className="intel-ref-card"
                      key={`${reference.database_id}:${reference.url}`}
                    >
                      <h4>{reference.database_name}</h4>
                      <a href={reference.url} target="_blank" rel="noopener noreferrer">
                        Abrir fuente
                      </a>
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section className="card results-card">
              <div className="results-toolbar">
                <input
                  value={searchTerm}
                  onChange={(event) => setSearchTerm(event.target.value)}
                  className="search-input"
                  placeholder="Buscar por paquete, CVE o descripcion"
                />

                <select
                  value={severityFilter}
                  onChange={(event) => setSeverityFilter(event.target.value as SeverityFilter)}
                  className="severity-select"
                >
                  <option value="all">Todas las severidades</option>
                  {severityOrder.map((severity) => (
                    <option key={severity} value={severity}>
                      {severityLabels[severity]}
                    </option>
                  ))}
                </select>

                {rawResults !== null && (
                  <button className="ghost-button" onClick={() => setShowRaw((prev) => !prev)}>
                    {showRaw ? "Ver panel" : "Ver JSON crudo"}
                  </button>
                )}
              </div>

              {showRaw && rawResults !== null ? (
                <pre className="raw-panel">{JSON.stringify(rawResults, null, 2)}</pre>
              ) : (
                <div className="result-list">
                  {filteredVulnerabilities.length === 0 ? (
                    <div className="empty-state">
                      {audit.summary.total_vulnerabilities === 0
                        ? "No se encontraron vulnerabilidades."
                        : "No hay coincidencias con los filtros actuales."}
                    </div>
                  ) : (
                    filteredVulnerabilities.map((vulnerability, index) => {
                      const severity = normalizeSeverity(vulnerability.severity);
                      const vulnKey = `${vulnerability.id || vulnerability.name}-${index}`;
                      const isExpanded = expandedDescriptions.has(vulnKey);
                      const lookupQuery = extractVulnerabilityQuery(vulnerability);
                      const hasLookupQuery = lookupQuery.length > 0;
                      const lookupType = hasLookupQuery
                        ? detectVulnerabilityIdType(lookupQuery)
                        : "GENERIC";
                      return (
                        <article className="vuln-card" key={vulnKey}>
                          <div className="vuln-top">
                            <div>
                              <h4>{vulnerability.name || vulnerability.package || "Vulnerabilidad"}</h4>
                              <p className="vuln-package">
                                {vulnerability.package || "unknown"} · version {vulnerability.version || "N/A"}
                              </p>
                            </div>
                            <span
                              className="severity-badge"
                              style={{ backgroundColor: `${severityColors[severity]}22`, color: severityColors[severity] }}
                            >
                              {severityLabels[severity]}
                            </span>
                          </div>

                          <div className="vuln-meta">
                            <span>
                              Fix: <strong>{vulnerability.fixed_in || vulnerability.fix_versions || "No disponible"}</strong>
                            </span>
                            {vulnerability.url && (
                              <a href={vulnerability.url} target="_blank" rel="noopener noreferrer">
                                Referencia
                              </a>
                            )}
                            {hasLookupQuery && (
                              <button
                                className="intel-link-button"
                                onClick={() => {
                                  setIntelQuery(lookupQuery);
                                  void fetchVulnerabilityReferences(lookupQuery);
                                }}
                              >
                                Mas fuentes ({lookupType})
                              </button>
                            )}
                            {vulnerability.description && (
                              <button 
                                className="expand-button"
                                onClick={() => {
                                  const newExpanded = new Set(expandedDescriptions);
                                  if (isExpanded) {
                                    newExpanded.delete(vulnKey);
                                  } else {
                                    newExpanded.add(vulnKey);
                                  }
                                  setExpandedDescriptions(newExpanded);
                                }}
                              >
                                {isExpanded ? "Ver menos" : "Ver más"}
                              </button>
                            )}
                          </div>

                          {isExpanded && vulnerability.description && (
                            <p className="vuln-description">{vulnerability.description}</p>
                          )}
                        </article>
                      );
                    })
                  )}
                </div>
              )}
            </section>
          </>
        )}
      </main>
    </div>
  );
}

export default Home;
