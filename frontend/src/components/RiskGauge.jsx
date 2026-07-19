import React from 'react';
import OsWindow from './OsWindow';

export default function RiskGauge({ score = 0, level = 'LOW', intentLabel = 'Unknown' }) {
  const getScoreColorClass = () => {
    if (level === 'LOW') return 'text-retro-green bg-black';
    if (level === 'SUSPICIOUS') return 'text-retro-yellow bg-black';
    return 'text-retro-red bg-black';
  };

  const getBadgeClasses = () => {
    let base = 'border-4 border-black px-4 py-2 inline-block font-mono font-bold text-sm shadow-mech ';
    if (level === 'LOW') return base + 'bg-retro-green text-black';
    if (level === 'SUSPICIOUS') return base + 'bg-retro-yellow text-black';
    return base + 'bg-retro-red text-white';
  };

  return (
    <OsWindow title="THREAT_ASSESSMENT.SYS">
      {/* Title row */}
      <div className="flex justify-between items-end mb-4">
        <div className="text-xs font-mono text-black font-bold uppercase pb-1">
          RISK SCORE
        </div>
        <div className="flex items-baseline gap-1 bg-black border-4 border-retro-gray p-2">
          <span className={`font-mono font-bold text-5xl px-2 ${getScoreColorClass()}`}>
            {score}
          </span>
          <span className="text-sm text-white font-mono">/100</span>
        </div>
      </div>

      {/* The gauge bar */}
      <div className="border-4 border-black bg-retro-gray p-1 flex w-full">
        {Array.from({ length: 20 }).map((_, index) => {
          let segmentBg = 'bg-white border-black border-2';
          
          if (score > index * 5) {
            if (index < 6) {
              segmentBg = 'bg-retro-green border-black border-2';
            } else if (index < 12) {
              segmentBg = 'bg-retro-yellow border-black border-2';
            } else {
              segmentBg = 'bg-retro-red border-black border-2';
            }
          }

          return (
            <div 
              key={index}
              className={`gauge-segment w-full mx-[1px] ${segmentBg}`}
            />
          );
        })}
      </div>

      {/* Bar Labels */}
      <div className="flex justify-between mt-2 text-xs font-mono font-bold text-black bg-retro-gray border-2 border-black px-2 py-1">
        <span>SAFE (0-30)</span>
        <span>SUSPICIOUS (31-60)</span>
        <span>HIGH RISK (61-100)</span>
      </div>

      {/* Threat level badge and Intent */}
      <div className="mt-6 flex flex-col gap-3">
        <div>
          <div className={getBadgeClasses()}>
            THREAT LEVEL: {level}
          </div>
        </div>
        <div className="font-mono text-sm font-bold text-black bg-white border-4 border-black p-2 shadow-mech">
          DETECTED INTENT: {intentLabel || 'Unknown'}
        </div>
      </div>
    </OsWindow>
  );
}
