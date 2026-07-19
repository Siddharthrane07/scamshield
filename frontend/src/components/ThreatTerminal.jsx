import React, { useState } from 'react';
import ScanlineOverlay from './ScanlineOverlay';
import IngestionPanel from './IngestionPanel';
import ResultsDashboard from './ResultsDashboard';
import OsWindow from './OsWindow';
import MechButton from './MechButton';
import { useScanApi } from '../hooks/useScanApi';

export default function ThreatTerminal() {
  const [appState, setAppState] = useState({
    mode: 'image',
    status: 'idle',
    scanId: null,
    result: null,
    error: null,
    explanationLang: 'en',
  });

  const [uploadedFile, setUploadedFile] = useState(null);
  
  const { scanImage, scanText } = useScanApi();

  const handleScanStart = async (type, payload) => {
    const newScanId = "SCAN_" + Date.now();
    setAppState(prev => ({
      ...prev,
      status: 'scanning',
      scanId: newScanId,
      error: null,
      result: null,
    }));

    try {
      let resultData;
      if (type === 'image') {
        resultData = await scanImage(payload);
      } else {
        resultData = await scanText(payload);
      }
      
      setAppState(prev => ({
        ...prev,
        status: 'complete',
        result: resultData,
      }));
    } catch (err) {
      setAppState(prev => ({
        ...prev,
        status: 'error',
        error: err.message,
      }));
    }
  };

  const handleReset = () => {
    setAppState(prev => ({
      ...prev,
      status: 'idle',
      scanId: null,
      result: null,
      error: null,
    }));
    setUploadedFile(null);
  };

  const setMode = (newMode) => {
    setAppState(prev => ({ ...prev, mode: newMode }));
  };

  return (
    <>
      {/* Header Menu Bar */}
      <header className="w-full h-8 bg-retro-gray border-b-2 border-black flex items-center justify-between px-2 z-50 relative">
        <div className="flex items-center gap-4 text-black text-xs font-mono">
          <span className="font-bold underline cursor-pointer">F</span>ile
          <span className="font-bold underline cursor-pointer">E</span>dit
          <span className="font-bold underline cursor-pointer">V</span>iew
          <span className="font-bold underline cursor-pointer">H</span>elp
        </div>
        <div className="hidden lg:flex flex-row gap-4">
          <span className="text-black text-xs font-mono">Status: ONLINE</span>
          <span className="text-black text-xs font-mono">API: OK</span>
        </div>
      </header>

      {/* Main Body Layout */}
      <main className="grid grid-cols-1 lg:grid-cols-2 gap-6 p-6 max-w-[1600px] mx-auto z-10 relative">
        {/* Left Column */}
        <div className="flex flex-col gap-6">
          <IngestionPanel 
            mode={appState.mode}
            setMode={setMode}
            onScanStart={handleScanStart}
            appStatus={appState.status}
            uploadedFile={uploadedFile}
            setUploadedFile={setUploadedFile}
          />
        </div>

        {/* Right Column */}
        <div className="flex flex-col gap-6">
          {appState.status === 'idle' && (
            <OsWindow title="RESULTS_MONITOR.EXE">
              <div className="min-h-[300px] bg-white flex flex-col items-center justify-center gap-4 border-2 border-black">
                <div className="font-mono text-sm text-black whitespace-pre text-center">
                  =============================={'\n'}
                  AWAITING THREAT PAYLOAD...{'\n'}
                  ==============================
                </div>
                <div className="flex flex-col text-xs text-black font-mono items-center mt-2">
                  <span>&gt; Upload screenshot or paste text</span>
                  <span>&gt; Execute scan to begin analysis</span>
                  <span>&gt; Results will render here &lt;</span>
                </div>
              </div>
            </OsWindow>
          )}

          {appState.status === 'scanning' && (
            <OsWindow title="ANALYSIS_ENGINE.EXE">
              <div className="min-h-[300px] bg-white flex flex-col items-center justify-center p-6 text-center relative overflow-hidden border-2 border-black">
                <div className="grid grid-cols-3 gap-2 mb-6">
                  {Array.from({ length: 9 }).map((_, i) => (
                    <div 
                      key={i} 
                      className="w-[20px] h-[20px] bg-retro-blue animate-pulse-dot border-2 border-black"
                      style={{ animationDelay: `${i * 150}ms` }}
                    />
                  ))}
                </div>
                <div className="font-mono text-xl text-black mb-4 font-bold">
                  SCANNING PAYLOAD...
                </div>
                <div className="font-mono text-xs text-black mb-4 tracking-widest">
                  TRACKS: A [|||   ] B [      ] C [      ] D [|     ]
                </div>
                <div className="text-xs text-black font-mono mt-4 border-t-2 border-black pt-2">
                  SCAN_ID: {appState.scanId || 'GENERATING...'}
                </div>
              </div>
            </OsWindow>
          )}

          {appState.status === 'complete' && (
            <ResultsDashboard result={appState.result} />
          )}

          {appState.status === 'error' && (
            <OsWindow title="SYSTEM_ERROR.LOG">
              <div className="flex flex-col gap-4">
                <div className="font-mono font-bold text-2xl text-retro-red text-center bg-white border-2 border-black p-2">
                  ⚠ SCAN FAILURE
                </div>
                <div className="font-mono text-sm text-black border-2 border-black bg-retro-beige p-3 break-words">
                  {appState.error}
                </div>
                <MechButton 
                  label="RESET TERMINAL" 
                  variant="danger" 
                  fullWidth={true} 
                  onClick={handleReset} 
                />
              </div>
            </OsWindow>
          )}
        </div>
      </main>
    </>
  );
}
