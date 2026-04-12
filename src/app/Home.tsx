import { useState } from "react";

type ParsedData = {
  type: "python" | "npm";
  dependencies: Record<string, string>;
};

function Home() {
  const [file, setFile] = useState<File | null>(null);
  const [parsed, setParsed] = useState<ParsedData | null>(null);

  const handleFileChange = async (
    e: React.ChangeEvent<HTMLInputElement>
  ) => {
    const selectedFile = e.target.files?.[0] || null;

    if (!selectedFile) return;

    const fileName = selectedFile.name;

    // Validar tipo de archivo
    if (
      fileName !== "requirements.txt" &&
      fileName !== "package.json"
    ) {
      alert("Solo se permiten archivos requirements.txt o package.json");
      return;
    }

    setFile(selectedFile);

    const text = await selectedFile.text();

    if (fileName === "requirements.txt") {
      const dependencies: Record<string, string> = {};

      text.split("\n").forEach((line) => {
        const clean = line.trim();
        if (!clean || clean.startsWith("#")) return;

        // Ej: numpy==1.24.0
        const [name, version] = clean.split("==");
        dependencies[name] = version || "latest";
      });

      setParsed({
        type: "python",
        dependencies,
      });
    }

    if (fileName === "package.json") {
      try {
        const json = JSON.parse(text);

        const dependencies = {
          ...(json.dependencies || {}),
          ...(json.devDependencies || {}),
        };

        setParsed({
          type: "npm",
          dependencies,
        });
      } catch (err) {
        alert("Error al parsear package.json");
      }
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        backgroundColor: "#ffffff",
        color: "#ffffff",
        fontFamily: "Segoe UI, sans-serif",
      }}
    >
      <header
        style={{
          padding: "1rem 2rem",
          backgroundColor: "#08172b",
          fontWeight: "bold",
          fontSize: "1.2rem",
        }}
      >
        AnalisisT
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
            background: "#08172b",
            padding: "2rem",
            borderRadius: "1rem",
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

          {parsed && (
            <pre
              style={{
                marginTop: "1rem",
                textAlign: "left",
                background: "#000",
                padding: "1rem",
                borderRadius: "0.5rem",
                maxHeight: "300px",
                overflow: "auto",
                fontSize: "0.8rem",
              }}
            >
              {JSON.stringify(parsed, null, 2)}
            </pre>
          )}
        </div>
      </main>
    </div>
  );
}

export default Home;