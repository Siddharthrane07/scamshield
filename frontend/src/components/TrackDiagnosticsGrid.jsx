import React from 'react';
import OsWindow from './OsWindow';

const TRACK_CONFIG = {
  url_intel:     { icon: '📄', name: 'TRACK A — URL INTEL' },
  domain_intel:  { icon: '🌐', name: 'TRACK B — DOMAIN INTEL' },
  sandbox:       { icon: '🗔', name: 'TRACK C — AWS SANDBOX' },
  ml_engine:     { icon: '⚙', name: 'TRACK D — ML ENGINE' },
};

function TrackCard({ name, icon, status, metrics, riskContribution }) {
  let statusClass = 'bg-white';
  let statusText = 'NOMINAL';
  let statusColor = 'text-retro-green';

  if (status === 'warn') {
    statusText = 'FLAGGED';
    statusColor = 'text-retro-yellow';
  } else if (status === 'fail' || status === 'error') {
    statusText = 'TIMEOUT/FAIL';
    statusColor = 'text-retro-red';
  } else if (status === 'skipped' || status === 'hostile_timeout') {
    statusText = 'SKIPPED';
    statusColor = 'text-gray-500';
  }

  return (
    <div className={`border-4 border-black p-3 shadow-mech ${statusClass}`}>
      <div className="flex justify-between items-start mb-2 border-b-2 border-black pb-2">
        <div className="flex items-center gap-2">
          <span className="text-xl">{icon}</span>
          <span className="text-sm font-mono font-bold text-black uppercase">
            {name}
          </span>
        </div>
        <span className={`text-xs font-bold font-mono whitespace-nowrap bg-black px-1 border-2 border-retro-gray ${statusColor}`}>
          {statusText}
        </span>
      </div>

      <div className="flex flex-col bg-retro-beige border-2 border-black p-2 min-h-[80px]">
        {metrics.map((m, i) => (
          <div 
            key={i} 
            className="text-xs font-mono text-black border-b border-gray-400 py-1 break-words font-bold"
          >
            {m.label}: {m.value}
          </div>
        ))}
      </div>

      <div className="text-xs font-mono font-bold bg-retro-gray border-2 border-black text-black px-2 py-1 inline-block mt-3 shadow-mech">
        WEIGHT: +{riskContribution}pts
      </div>
    </div>
  );
}

export default function TrackDiagnosticsGrid({ tracks }) {
  if (!tracks) return null;

  const urlIntel = tracks.url_intel || {};
  const domainIntel = tracks.domain_intel || {};
  const sandbox = tracks.sandbox || {};
  const mlEngine = tracks.ml_engine || {};

  const getUrlMetrics = () => {
    if (urlIntel.status === 'skipped') return [{ label: 'STATUS', value: 'N/A' }];
    const metrics = [];
    metrics.push({ label: 'FLAGS', value: urlIntel.flags?.length || 0 });
    if (urlIntel.virustotal_hits !== undefined) {
      metrics.push({ label: 'VT_HITS', value: urlIntel.virustotal_hits });
    }
    metrics.push({ label: 'TYPOSQUAT', value: urlIntel.typosquat_detected ? 'TRUE' : 'FALSE' });
    return metrics;
  };

  const getDomainMetrics = () => {
    if (domainIntel.status === 'skipped') return [{ label: 'STATUS', value: 'N/A' }];
    const metrics = [];
    if (domainIntel.domain_age_hours !== undefined) {
      metrics.push({ label: 'AGE_HOURS', value: domainIntel.domain_age_hours });
    }
    if (domainIntel.ssl_valid !== undefined) {
      metrics.push({ label: 'SSL_VALID', value: domainIntel.ssl_valid ? 'TRUE' : 'FALSE' });
    }
    if (domainIntel.registrar) {
      metrics.push({ label: 'REGISTRAR', value: domainIntel.registrar });
    }
    return metrics;
  };

  const getSandboxMetrics = () => {
    if (sandbox.status === 'skipped' || sandbox.status === 'hostile_timeout') {
      return [{ label: 'STATUS', value: 'N/A' }];
    }
    const metrics = [];
    if (sandbox.dom_auth_inputs !== undefined) {
      metrics.push({ label: 'AUTH_INPUTS', value: sandbox.dom_auth_inputs ? 'TRUE' : 'FALSE' });
    }
    if (sandbox.redirect_count !== undefined) {
      metrics.push({ label: 'REDIRECTS', value: sandbox.redirect_count });
    }
    return metrics;
  };

  const getMlMetrics = () => {
    if (mlEngine.status === 'error' || !mlEngine.intent_label) {
      return [{ label: 'STATUS', value: 'N/A' }];
    }
    const metrics = [];
    if (mlEngine.confidence !== undefined) {
      metrics.push({ label: 'CONFIDENCE', value: `${(mlEngine.confidence * 100).toFixed(1)}%` });
    }
    if (mlEngine.social_labels && mlEngine.social_labels.length > 0) {
      metrics.push({ label: 'LABELS', value: mlEngine.social_labels.join(' + ') });
    }
    if (mlEngine.intent_label) {
      metrics.push({ label: 'INTENT', value: mlEngine.intent_label });
    }
    return metrics;
  };

  return (
    <OsWindow title="CONTROL_PANEL.CPL">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-retro-gray p-2 border-4 border-black">
        <TrackCard 
          {...TRACK_CONFIG.url_intel}
          status={urlIntel.status || 'skipped'}
          metrics={getUrlMetrics()}
          riskContribution={urlIntel.risk_contribution || 0}
        />
        <TrackCard 
          {...TRACK_CONFIG.domain_intel}
          status={domainIntel.status || 'skipped'}
          metrics={getDomainMetrics()}
          riskContribution={domainIntel.risk_contribution || 0}
        />
        <TrackCard 
          {...TRACK_CONFIG.sandbox}
          status={sandbox.status || 'skipped'}
          metrics={getSandboxMetrics()}
          riskContribution={sandbox.risk_contribution || 0}
        />
        <TrackCard 
          {...TRACK_CONFIG.ml_engine}
          status={mlEngine.status || 'error'}
          metrics={getMlMetrics()}
          riskContribution={mlEngine.risk_contribution || 0}
        />
      </div>
    </OsWindow>
  );
}
