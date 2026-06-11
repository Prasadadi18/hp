import React, { useEffect, useState } from 'react';

export default function IframeSection({ tabId, port, active }) {
  const [src, setSrc] = useState('');

  useEffect(() => {
    if (active && !src) {
      const hostname = window.location.hostname || 'localhost';
      setSrc(`http://${hostname}:${port}`);
    }
  }, [active, src, port]);

  return (
    <section
      className={`section ${active ? 'active' : ''}`}
      id={tabId}
      style={{ padding: 0, overflow: 'hidden' }}
    >
      {src && (
        <iframe
          src={src}
          style={{
            width: '100%',
            height: '100%',
            border: 'none',
            background: 'var(--bg-void)',
          }}
          title={tabId}
        />
      )}
    </section>
  );
}
