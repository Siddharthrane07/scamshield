import React from 'react';

export default function OsWindow({ title, children, className = '', statusDot = null }) {
  return (
    <div className={`border-4 border-black bg-retro-gray shadow-window ${className}`}>
      {/* Title Bar */}
      <div className="os-window-title-bar">
        <div className="flex items-center gap-3">
          <span className="text-xs font-bold tracking-widest font-mono uppercase text-white">
            {title}
          </span>
        </div>
        <div className="os-window-close-btn">X</div>
      </div>
      {/* Content Area */}
      <div className="p-4 m-1 border-2 border-black bg-white">
        {children}
      </div>
    </div>
  );
}
