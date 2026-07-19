import React from 'react';
import OsWindow from './OsWindow';

export default function EvidenceViewer({ base64 }) {
  if (!base64) return null;

  return (
    <OsWindow title="MSPAINT.EXE - EVIDENCE_CAPTURE.PNG">
      <div className="flex bg-retro-gray border-b-2 border-black p-1 gap-2 mb-2">
        <div className="text-xs font-mono font-bold text-black border-2 border-transparent hover:border-black cursor-pointer px-1">File</div>
        <div className="text-xs font-mono font-bold text-black border-2 border-transparent hover:border-black cursor-pointer px-1">Edit</div>
        <div className="text-xs font-mono font-bold text-black border-2 border-transparent hover:border-black cursor-pointer px-1">View</div>
        <div className="text-xs font-mono font-bold text-black border-2 border-transparent hover:border-black cursor-pointer px-1">Image</div>
        <div className="text-xs font-mono font-bold text-black border-2 border-transparent hover:border-black cursor-pointer px-1">Options</div>
        <div className="text-xs font-mono font-bold text-black border-2 border-transparent hover:border-black cursor-pointer px-1">Help</div>
      </div>

      <div className="bg-retro-gray p-2 border-4 border-black flex flex-col md:flex-row gap-2">
        {/* Fake tool palette */}
        <div className="hidden md:grid grid-cols-2 gap-1 bg-retro-gray border-2 border-black p-1 w-12 h-[150px]">
          {Array.from({ length: 12 }).map((_, i) => (
            <div key={i} className="bg-white border-2 border-black hover:bg-black cursor-pointer" />
          ))}
        </div>

        {/* The image canvas */}
        <div className="border-4 border-black bg-white p-2 flex-grow overflow-hidden shadow-mech">
          <img 
            src={`data:image/png;base64,${base64}`} 
            alt="Sandbox capture"
            className="w-full object-contain max-h-[300px] border-2 border-black"
            loading="lazy"
          />
        </div>
      </div>
      
      <div className="border-t-2 border-black pt-1 mt-2 text-xs font-mono text-black font-bold flex justify-between bg-retro-gray px-1 border-x-2 border-b-2 shadow-mech">
        <span>For Help, click Help Topics on the Help Menu.</span>
        <span>240x240</span>
      </div>
    </OsWindow>
  );
}
