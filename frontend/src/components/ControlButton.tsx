import React from 'react';
import { Shield } from 'lucide-react';
import clsx from 'clsx';

interface Props {
  capturing: boolean;
  onToggle: () => void;
}

export default function ControlButton({ capturing, onToggle }: Props) {
  return (
    <button
      onClick={onToggle}
      className={clsx(
        'px-6 py-3 md:py-6 rounded-xl text-xl md:text-xl font-extrabold transition-transform transform hover:scale-105 shadow-2xl flex items-center gap-2 h-fit',
        capturing
          ? 'bg-red-600 hover:bg-red-500 text-white border-1 border-red-200'
          : 'bg-blue-600 hover:bg-blue-500 text-white border-1 border-blue-200'
      )}
    >
      <Shield className="w-4 h-4 md:w-6 md:h-6" />
      {capturing ? 'STOP CAPTURE' : 'START CAPTURE'}
    </button>
  );
}