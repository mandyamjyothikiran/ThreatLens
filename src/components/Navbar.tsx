import React from 'react';
import { PageId } from '../types';
import { Menu, Play } from 'lucide-react';

interface NavbarProps {
  currentPage: PageId;
  apiConnected: boolean;
  isMonitoringActive: boolean;
  onOpenMobileSidebar: () => void;
  onOpenLivePredict: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentPage,
  apiConnected,
  isMonitoringActive,
  onOpenMobileSidebar,
  onOpenLivePredict
}) => {
  const pageTitles: Record<PageId, string> = {
    dashboard: 'Dashboard',
    live_monitoring: 'Live Monitoring',
    alerts: 'Threat Alerts',
    ml_model: 'ML Model',
    evaluation: 'Ground Truth Evaluation',
    settings: 'Settings'
  };

  return (
    <header className="h-16 bg-[#070d1e] border-b border-slate-800/80 px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Left: Mobile menu toggle & page title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onOpenMobileSidebar}
          className="p-1.5 text-slate-400 hover:text-white rounded md:hidden"
          aria-label="Open sidebar"
        >
          <Menu className="w-5 h-5" />
        </button>

        <h1 className="text-base font-semibold text-white tracking-tight">
          {pageTitles[currentPage] || 'Dashboard'}
        </h1>
      </div>

      {/* Right: Live status indicator, backend health, and action button */}
      <div className="flex items-center gap-4">
        {/* Live monitoring status */}
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span
            className={`w-2 h-2 rounded-full ${
              isMonitoringActive ? 'bg-cyan-400 animate-pulse' : 'bg-slate-600'
            }`}
          />
          <span className="hidden sm:inline">Live Monitoring:</span>
          <span className={isMonitoringActive ? 'text-cyan-400 font-medium' : 'text-slate-400'}>
            {isMonitoringActive ? 'Active' : 'Inactive'}
          </span>
        </div>

        {/* Backend connectivity indicator */}
        <div className="hidden lg:flex items-center gap-1.5 text-xs font-mono text-slate-400 pl-3 border-l border-slate-800">
          <span
            className={`w-2 h-2 rounded-full ${
              apiConnected ? 'bg-emerald-400' : 'bg-amber-400'
            }`}
          />
          <span>{apiConnected ? 'Connected' : 'Connecting...'}</span>
        </div>

        {/* Test Flow Action */}
        <button
          onClick={onOpenLivePredict}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors shadow-xs"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span className="hidden sm:inline">Test Flow</span>
        </button>
      </div>
    </header>
  );
};
