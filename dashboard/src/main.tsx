import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { App } from './App';
import { Layout } from './Layout';
import { ScanDetail } from './ScanDetail';
import { AuditTimeline } from './pages/AuditTimeline';
import { Browse } from './pages/Browse';
import { ManifestViewer } from './pages/ManifestViewer';
import { Policies } from './pages/Policies';
import { ProjectList } from './pages/ProjectList';
import { RepoList } from './pages/RepoList';
import { TagList } from './pages/TagList';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<App />} />
          <Route path="/browse" element={<Browse />} />
          <Route path="/t/:tenant" element={<ProjectList />} />
          <Route path="/t/:tenant/:project" element={<RepoList />} />
          <Route path="/t/:tenant/:project/:repo" element={<TagList />} />
          <Route
            path="/t/:tenant/:project/:repo/manifest/:ref"
            element={<ManifestViewer />}
          />
          <Route path="/scan/:digest" element={<ScanDetail />} />
          <Route path="/audit" element={<AuditTimeline />} />
          <Route path="/policies" element={<Policies />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>,
);
