import React from 'react';

export default function MechButton({
  label,
  onClick,
  variant = 'default',
  size = 'md',
  disabled = false,
  isLoading = false,
  fullWidth = false,
}) {
  const getVariantClasses = () => {
    switch (variant) {
      case 'execute': return 'bg-retro-gray hover:bg-retro-green text-black border-black';
      case 'danger': return 'bg-retro-gray hover:bg-retro-red text-black border-black';
      case 'ghost': return 'bg-white text-black border-black';
      default: return 'bg-retro-gray text-black border-black';
    }
  };

  const getSizeClasses = () => {
    switch (size) {
      case 'sm': return 'px-3 py-1 text-xs border-4';
      case 'lg': return 'px-8 py-4 text-base tracking-widest border-4';
      default: return 'px-5 py-2 text-sm border-4';
    }
  };

  const baseClasses = `
    mech-btn 
    rounded-none 
    font-mono 
    font-bold 
    uppercase 
    tracking-wider
    ${getVariantClasses()}
    ${getSizeClasses()}
    ${fullWidth ? 'w-full' : ''}
    ${(disabled || isLoading) ? 'cursor-not-allowed opacity-50 hover:bg-retro-gray' : ''}
  `.replace(/\s+/g, ' ').trim();

  const handleKeyDown = (e) => {
    if ((e.key === 'Enter' || e.key === ' ') && !disabled && !isLoading) {
      e.preventDefault();
      onClick();
    }
  };

  return (
    <button
      className={baseClasses}
      onClick={(disabled || isLoading) ? undefined : onClick}
      disabled={disabled || isLoading}
      aria-label={label}
      role="button"
      tabIndex={0}
      onKeyDown={handleKeyDown}
    >
      {isLoading ? (
        <span>PROCESSING<span className="animate-cursor-blink">_</span></span>
      ) : (
        label
      )}
    </button>
  );
}
