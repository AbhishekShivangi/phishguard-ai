import { useState } from "react";
import axios from "axios";

export default function App() {
  const [url, setUrl] = useState("");
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);

  const scanURL = async () => {
    const res = await axios.post("http://localhost:5000/predict/url", { url });
    setResult(res.data);
  };

  const scanText = async () => {
    const res = await axios.post("http://localhost:5000/predict/text", { text });
    setResult(res.data);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6">
      
      {/* TITLE */}
      <h1 className="text-4xl font-bold text-blue-400 mb-6">
        🛡️ PhishGuard AI
      </h1>

      {/* PITCH SECTION */}
      <div className="bg-gray-800 p-4 rounded-lg mb-6">
        <p>
          🚀 Our AI system detects zero-day phishing attacks using machine learning 
          and real-time analysis, helping users stay safe from evolving cyber threats.
        </p>
      </div>

      {/* URL SCANNER */}
      <div className="mb-6">
        <h2 className="text-xl mb-2">🔗 URL Scanner</h2>
        <input
          className="p-2 w-full text-black"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter URL"
        />
        <button onClick={scanURL} className="mt-2 bg-blue-500 px-4 py-2">
          Scan URL
        </button>
      </div>

      {/* TEXT SCANNER */}
      <div className="mb-6">
        <h2 className="text-xl mb-2">📩 SMS/Email Scanner</h2>
        <textarea
          className="p-2 w-full text-black"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
        <button onClick={scanText} className="mt-2 bg-green-500 px-4 py-2">
          Scan Text
        </button>
      </div>

      {/* RESULT */}
      {result && (
        <div className="bg-gray-800 p-4 rounded-lg">
          <h3 className="text-xl">
            Result: 
            <span className={
              result.prediction === "Safe"
                ? "text-green-400"
                : "text-red-400"
            }>
              {" "}{result.prediction}
            </span>
          </h3>

          <p>Confidence: {result.confidence}%</p>

          {result.reasons && (
            <ul>
              {result.reasons.map((r, i) => (
                <li key={i}>⚠️ {r}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
