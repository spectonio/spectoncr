import { useEffect, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { getApiKey, setApiKey } from './api';
import { PilotSidebar } from './PilotSidebar';
import { Header } from './ui';

/** Root shell: steel header, nav, API key, pilot sidebar, routed page content. */
export function Layout() {
  const [key, setKey] = useState(getApiKey() || '');

  useEffect(() => {
    setApiKey(key);
  }, [key]);

  const conn = (
    <div className="conn" title={key ? 'API key set' : 'No API key — registry calls may be rejected'}>
      <span className={`conn-dot ${key ? 'on' : ''}`} aria-hidden="true" />
      <input
        type="password"
        value={key}
        onChange={(e) => setKey(e.target.value)}
        placeholder="API key (nck_…)"
        aria-label="API key"
      />
    </div>
  );

  return (
    <div className="shell">
      <Header right={conn} />
      <PilotSidebar />
      <Outlet />
    </div>
  );
}
