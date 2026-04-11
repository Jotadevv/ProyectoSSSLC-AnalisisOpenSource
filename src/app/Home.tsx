import { useState } from "react";

function Home() {
  const [file, setFile] = useState<File | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0] || null;
    setFile(selectedFile);
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        margin: 0,
        display: "flex",
        flexDirection: "column",
        backgroundColor: "#ffffff",
        color: "#ffffff",
        fontFamily: "Segoe UI, sans-serif",
      }}
    >
      {/* Header */}
      <header
        style={{
          padding: "1rem 2rem",
          backgroundColor: "#08172b",
          boxShadow: "0 4px 10px rgba(0,0,0,0.3)",
          fontWeight: "bold",
          fontSize: "1.2rem",
        }}
      >
        AnalisisT
      </header>

      {/* Main content */}
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
            boxShadow: "0 10px 30px rgba(0,0,0,0.4)",
          }}
        >
          <h1 style={{ marginBottom: "1.5rem", fontSize: "2rem" }}>
            Bienvenido a AnalisisT
          </h1>

          <input
            type="file"
            onChange={handleFileChange}
            style={{
              marginBottom: "1rem",
              padding: "0.5rem",
              borderRadius: "0.5rem",
              border: "none",
            }}
          />

          {file && (
            <p style={{ fontSize: "0.9rem", opacity: 0.8 }}>
              Archivo seleccionado: {file.name}
            </p>
          )}
        </div>
      </main>
    </div>
  );
}

export default Home;