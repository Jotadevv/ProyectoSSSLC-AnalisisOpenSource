import { useState } from "react";

type Vulnerability = {
  name?: string;
  package?: string;
  version?: string;
  severity?: string;
  fix_versions?: string;
  fixed_in?: string;
  description?: string;
  url?: string;
};

function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [results, setResults] = useState<Vulnerability[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rawResults, setRawResults] = useState<any | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  const handleFileChange = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const selectedFile = e.target.files?.[0] || null;
    if (!selectedFile) return;

    const fileName = selectedFile.name;

    if (
      fileName !== "requirements.txt" &&
      fileName !== "package.json"
    ) {
      alert("Solo se permiten requirements.txt o package.json");
      return;
    }

    setFile(selectedFile);
    setLoading(true);
    setResults(null);
    setError(null);
    setRawResults(null);
    setShowRaw(false);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const endpoint =
        fileName === "requirements.txt"
          ? "http://localhost:8000/audit/python"
          : "http://localhost:8000/audit/npm";

      const res = await fetch(endpoint, {
        method: "POST",
        body: formData,
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data?.error || "Error ejecutando auditoría");
        setResults([]);
      } else if (Array.isArray(data)) {
        setResults(data);
      } else if (data?.vulnerabilities) {
        setResults(data.vulnerabilities);
      } else if (data?.error) {
        setError(data.error);
        setResults([]);
      } else {
        setResults([]);
      }

      // Si es requirements.txt, cargar también los resultados crudos
      if (fileName === "requirements.txt" && res.ok) {
        try {
          const rawRes = await fetch("http://localhost:8000/audit/python_output");
          if (rawRes.ok) {
            const rawData = await rawRes.json();
            setRawResults(rawData);
          }
        } catch (rawErr) {
          console.error("Error cargando resultados crudos:", rawErr);
        }
      }
    } catch (err) {
      console.error(err);
      setError("Error ejecutando auditoría");
      setResults([]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        backgroundColor: "#0f172a",
        color: "#fff",
        fontFamily: "Segoe UI, sans-serif",
      }}
    >
      <header
        style={{
          padding: "1rem 2rem",
          backgroundColor: "#020617",
          fontWeight: "bold",
          fontSize: "1.2rem",
        }}
      >
        AnalisisT 🔍
      </header>

      <main
        style={{
          flex: 1,
          display: "grid",
          placeItems: "center",
          padding: "2rem",
        }}
      >
        <div
          style={{
            textAlign: "center",
            background: "#020617",
            padding: "2rem",
            borderRadius: "1rem",
            width: "100%",
            maxWidth: "600px",
          }}
        >
          <h1 style={{ marginBottom: "1.5rem" }}>
            Analizador de dependencias
          </h1>

          <input
            type="file"
            accept=".txt,.json"
            onChange={handleFileChange}
          />

          {file && (
            <p style={{ marginTop: "1rem" }}>
              Archivo: {file.name}
            </p>
          )}

          {loading && (
            <p style={{ marginTop: "1rem", color: "#38bdf8" }}>
              🔄 Analizando vulnerabilidades...
            </p>
          )}

          {error && (
            <div
              style={{
                marginTop: "1rem",
                textAlign: "left",
                background: "#7f1d1d",
                padding: "1rem",
                borderRadius: "0.5rem",
                color: "#fff",
                maxHeight: "300px",
                overflow: "auto",
                fontSize: "0.85rem",
              }}
            >
              <strong>Error:</strong> {error}
            </div>
          )}

          {results && !error && (
            <div
              style={{
                marginTop: "1rem",
                textAlign: "left",
                background: "#000",
                padding: "1rem",
                borderRadius: "0.5rem",
                maxHeight: "300px",
                overflow: "auto",
                fontSize: "0.85rem",
              }}
            >
              {rawResults && (
                <div style={{ marginBottom: "1rem" }}>
                  <button
                    onClick={() => setShowRaw(!showRaw)}
                    style={{
                      background: "#38bdf8",
                      color: "#000",
                      border: "none",
                      padding: "0.5rem 1rem",
                      borderRadius: "0.25rem",
                      cursor: "pointer",
                      fontSize: "0.8rem",
                    }}
                  >
                    {showRaw ? "Ver resultados procesados" : "Ver resultados crudos"}
                  </button>
                </div>
              )}

              {showRaw && rawResults ? (
                <div>
                  <h3 style={{ marginBottom: "0.5rem", color: "#38bdf8" }}>
                    Resultados crudos de pip-audit:
                  </h3>
                  <pre
                    style={{
                      background: "#111",
                      padding: "0.5rem",
                      borderRadius: "0.25rem",
                      fontSize: "0.7rem",
                      overflow: "auto",
                      maxHeight: "200px",
                    }}
                  >
                    {JSON.stringify(rawResults, null, 2)}
                  </pre>
                </div>
              ) : (
                <>
                  {results.length === 0 ? (
                    <p style={{ color: "#4ade80" }}>
                      ✅ No se encontraron vulnerabilidades
                    </p>
                  ) : (
                    results.map((vuln, i) => (
                      <div
                        key={i}
                        style={{
                          marginBottom: "0.75rem",
                          padding: "0.5rem",
                          borderBottom: "1px solid #222",
                        }}
                      >
                        <strong>
                          {vuln.name || vuln.package}
                        </strong>
                        <br />
                        Versión: {vuln.version || "N/A"} <br />
                        Severidad:{" "}
                        <span
                          style={{
                            color:
                              vuln.severity === "high"
                                ? "red"
                                : vuln.severity === "moderate"
                                ? "orange"
                                : "#ccc",
                          }}
                        >
                          {vuln.severity || "unknown"}
                        </span>
                        <br />
                        Fix:{" "}
                        {vuln.fix_versions ||
                          vuln.fixed_in ||
                          "No disponible"}
                        {vuln.url && (
                          <p style={{ margin: "0.25rem 0", fontSize: "0.8rem" }}>
                            <a href={vuln.url} target="_blank" rel="noopener noreferrer" 
                               style={{ color: "#60a5fa", textDecoration: "underline" }}>
                              Más información
                            </a>
                          </p>
                        )}
                        {vuln.description && (
                          <p style={{ margin: "0.5rem 0 0", color: "#cbd5e1" }}>
                            {vuln.description}
                          </p>
                        )}
                      </div>
                    ))
                  )}
                </>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

export default Home;