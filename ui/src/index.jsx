import { createRoot } from "react-dom/client";
import App from "./App";
import ErrorBoundary from "./components/ErrorBoundary";
import "./index.css";

const domNode = document.getElementById('root');
const root = createRoot(domNode);
root.render(
  <ErrorBoundary>
    <App />
  </ErrorBoundary>);
