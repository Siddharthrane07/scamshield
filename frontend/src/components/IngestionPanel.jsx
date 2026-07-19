import React, { useRef, useState } from 'react';
import OsWindow from './OsWindow';
import MechButton from './MechButton';

export default function IngestionPanel({ mode, setMode, onScanStart, appStatus, uploadedFile, setUploadedFile }) {
  const [dragActive, setDragActive] = useState(false);
  const [textValue, setTextValue] = useState('');
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setUploadedFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    e.preventDefault();
    if (e.target.files && e.target.files[0]) {
      setUploadedFile(e.target.files[0]);
    }
  };

  const handleScan = () => {
    if (mode === 'image' && uploadedFile) {
      onScanStart('image', uploadedFile);
    } else if (mode === 'text' && textValue) {
      onScanStart('text', textValue);
    }
  };

  const isScanning = appStatus === 'scanning';
  const isExecuteDisabled = isScanning || (mode === 'image' && !uploadedFile) || (mode === 'text' && !textValue);

  return (
    <OsWindow title="INGESTION_MODULE.EXE">
      {/* Mode Toggle */}
      <div className="flex mb-4">
        <button
          className={`mech-btn border-4 border-black px-6 py-2 text-sm font-mono font-bold uppercase w-1/2 rounded-none
            ${mode === 'image' ? 'bg-white text-black' : 'bg-retro-gray text-black shadow-mech'}`}
          onClick={() => setMode('image')}
        >
          IMAGE
        </button>
        <button
          className={`mech-btn border-4 border-black px-6 py-2 text-sm font-mono font-bold uppercase w-1/2 rounded-none
            ${mode === 'text' ? 'bg-white text-black' : 'bg-retro-gray text-black shadow-mech'}`}
          onClick={() => setMode('text')}
        >
          TEXT
        </button>
      </div>

      {/* Input Area */}
      <div className="mb-4">
        {mode === 'image' ? (
          <div 
            className={`border-4 border-dashed border-black bg-white min-h-[200px] flex flex-col items-center justify-center cursor-pointer gap-3 p-4
              ${dragActive ? 'bg-retro-gray' : ''}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => !uploadedFile && fileInputRef.current?.click()}
            role="button"
            aria-label="Upload scam screenshot"
            tabIndex={0}
            onKeyDown={(e) => {
              if ((e.key === 'Enter' || e.key === ' ') && !uploadedFile) {
                e.preventDefault();
                fileInputRef.current?.click();
              }
            }}
          >
            <input 
              type="file" 
              accept="image/*" 
              ref={fileInputRef} 
              className="hidden" 
              onChange={handleChange}
            />

            {!uploadedFile ? (
              <>
                <div className="text-4xl text-black">📁</div>
                <div className="font-mono font-bold text-xl text-black">DROP SCREENSHOT HERE</div>
                <div className="font-mono text-xs text-black">OR CLICK TO BROWSE</div>
                <div className="text-xs text-black font-mono mt-2 bg-retro-beige px-2 border-2 border-black">.PNG .JPG .WEBP — MAX 10MB</div>
              </>
            ) : (
              <>
                <div className="border-2 border-black px-2 py-1 font-mono text-xs text-white bg-retro-blue">
                  {uploadedFile.name}
                </div>
                <img 
                  src={URL.createObjectURL(uploadedFile)} 
                  alt="Preview" 
                  className="max-h-[150px] object-contain border-4 border-black bg-white"
                />
                <div className="mt-2" onClick={(e) => e.stopPropagation()}>
                  <MechButton 
                    label="X REMOVE" 
                    size="sm" 
                    variant="danger" 
                    onClick={() => {
                      setUploadedFile(null);
                      if (fileInputRef.current) fileInputRef.current.value = '';
                    }}
                  />
                </div>
              </>
            )}
          </div>
        ) : (
          <textarea
            className="w-full min-h-[200px] bg-white text-black font-mono text-sm p-3 border-4 border-black resize-none outline-none focus:border-retro-blue placeholder:text-gray-500"
            placeholder="PASTE SCAM MESSAGE HERE...&#10;> HINDI, ENGLISH, HINGLISH SUPPORTED&#10;> URLS AND UPI IDs WILL BE EXTRACTED AUTOMATICALLY&#10;_"
            value={textValue}
            onChange={(e) => setTextValue(e.target.value)}
          />
        )}
      </div>

      {/* Scan Info Strip */}
      <div className="bg-retro-beige border-y-2 border-black p-2 mb-4">
        <div className="text-xs font-mono text-black font-bold flex justify-between">
          <span>MODE: {mode.toUpperCase()} SCAN</span>
          <span>ENGINE: XLM-ROBERTA ONNX // TRACKS: 4</span>
        </div>
      </div>

      {/* Execute Button */}
      <MechButton
        label="EXECUTE SCAN"
        variant="execute"
        size="lg"
        fullWidth={true}
        disabled={isExecuteDisabled}
        isLoading={isScanning}
        onClick={handleScan}
      />
    </OsWindow>
  );
}
