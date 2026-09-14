import React from 'react';
import RiskGauge from './RiskGauge';
import TrackDiagnosticsGrid from './TrackDiagnosticsGrid';
import BilingualOutput from './BilingualOutput';
import EvidenceViewer from './EvidenceViewer';

export default function ResultsDashboard({ result }) {
  if (!result) return null;

  // 1. Extract Score and Threat Level
  const score = result.risk_score ?? 0;
  let level = 'LOW';
  if (score > 60) {
    level = 'HIGH';
  } else if (score > 30) {
    level = 'SUSPICIOUS';
  }

  // 2. Extract ML Intent and Triggers
  const rawTracks = result.metadata?.track_details || result.tracks || {};
  const rawMl = rawTracks.track_d_ml_engine || rawTracks.ml_engine || {};
  const detectedIntent = rawMl.scam_intent?.detected_intent || result.intent_label || 'Unknown';

  // 3. Extract Bilingual Explanations
  const explanationEn = result.explanations?.en || result.explanation_en || '';
  const explanationHi = result.explanations?.hi || result.explanation_hi || '';

  // 4. Normalize Track Details for TrackDiagnosticsGrid
  const rawUrl = rawTracks.track_a_url_intel || rawTracks.url_intel || {};
  const rawDomain = rawTracks.track_b_domain_intel || rawTracks.domain_intel || {};
  const rawSandbox = rawTracks.track_c_sandbox || rawTracks.sandbox || {};

  const normalizedTracks = {
    url_intel: {
      status: rawUrl.status === 'bypassed' ? 'skipped' : (rawUrl.max_risk_score > 50 ? 'warn' : 'nominal'),
      flags: rawUrl.urls_analyzed?.flatMap(u => u.flags || []) || [],
      virustotal_hits: rawUrl.urls_analyzed?.filter(u => u.virustotal?.verdict === 'malicious').length,
      typosquat_detected: rawUrl.urls_analyzed?.some(u => u.typosquatting?.is_typosquatted),
      risk_contribution: rawUrl.max_risk_score || 0
    },
    domain_intel: {
      status: rawDomain.status === 'bypassed' ? 'skipped' : (rawDomain.max_risk_score > 50 ? 'warn' : 'nominal'),
      domain_age_hours: rawDomain.domains_analyzed?.[0]?.whois?.age_hours,
      ssl_valid: rawDomain.domains_analyzed?.[0]?.ssl?.ssl_valid,
      registrar: rawDomain.domains_analyzed?.[0]?.whois?.registrar,
      risk_contribution: rawDomain.max_risk_score || 0
    },
    sandbox: {
      status: rawSandbox.status === 'bypassed' ? 'skipped' : (rawSandbox.sandbox_status || 'skipped'),
      dom_auth_inputs: rawSandbox.dom_signals?.has_auth_inputs,
      redirect_count: rawSandbox.dom_signals?.redirect_count || 0,
      risk_contribution: rawSandbox.risk_weight || 0
    },
    ml_engine: {
      status: rawMl.is_scam ? 'warn' : 'nominal',
      confidence: rawMl.scam_intent?.confidence,
      social_labels: rawMl.social_engineering_triggers || Object.keys(rawMl.social_engineering || {}).filter(k => !k.startsWith('social_') && rawMl.social_engineering[k] >= 0.5),
      intent_label: detectedIntent,
      risk_contribution: rawMl.risk_score || score
    }
  };

  // 5. Check if screenshot is a real capture (exclude 1x1 transparent dummy PNG)
  const isDummyPng = !result.screenshot_base64 || 
    result.screenshot_base64 === "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=" ||
    result.screenshot_base64.length < 150;

  return (
    <div className="flex flex-col gap-4">
      <RiskGauge 
        score={score} 
        level={level} 
        intentLabel={detectedIntent}
      />
      
      <TrackDiagnosticsGrid tracks={normalizedTracks} />
      
      <BilingualOutput 
        en={explanationEn} 
        hi={explanationHi} 
      />
      
      {!isDummyPng && (
        <EvidenceViewer base64={result.screenshot_base64} />
      )}
    </div>
  );
}
