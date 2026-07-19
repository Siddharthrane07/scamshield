import React from 'react';
import RiskGauge from './RiskGauge';
import TrackDiagnosticsGrid from './TrackDiagnosticsGrid';
import BilingualOutput from './BilingualOutput';
import EvidenceViewer from './EvidenceViewer';

export default function ResultsDashboard({ result }) {
  if (!result) return null;

  return (
    <div className="flex flex-col gap-4">
      <RiskGauge 
        score={result.risk_score} 
        level={result.threat_level} 
        intentLabel={result.intent_label}
      />
      
      <TrackDiagnosticsGrid tracks={result.tracks} />
      
      <BilingualOutput 
        en={result.explanation_en} 
        hi={result.explanation_hi} 
      />
      
      {result.screenshot_base64 && (
        <EvidenceViewer base64={result.screenshot_base64} />
      )}
    </div>
  );
}
