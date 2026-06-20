import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './styles/index.css';

// NOTE: StrictMode is intentionally NOT used. The app runs the Vite dev server
// (npm run dev), where StrictMode double-invokes effects on mount — that opened
// TWO /ws/simulate WebSocket connections, so every event was received and
// rendered twice (pipeline animated twice, event log duplicated). Rendering
// without StrictMode gives a single WS connection and correct, single events.
ReactDOM.createRoot(document.getElementById('root')).render(
  <App />
);
