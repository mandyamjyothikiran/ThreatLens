import React from 'react';
import { PageId } from '../types';
import {
  LayoutDashboard,
  Radio,
  AlertTriangle,
  Cpu,
  Settings,
  Shield,
  X,
  FileCheck
} from 'lucide-react';

interface SidebarProps {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
  alertCount: number;
  isMonitoringActive: boolean;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  alertCount,
  isMonitoringActive,
  isOpenMobile,
  onCloseMobile
}) => {
  const navItems: Array<{ id: PageId; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }> = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'live_monitoring', label: 'Live Monitoring', icon: Radio },
    { id: 'alerts', label: 'Threat Alerts', icon: AlertTriangle, count: alertCount },
    { id: 'ml_model', label: 'ML Model', icon: Cpu },
    { id: 'evaluation', label: 'Ground Truth Evaluation', icon: FileCheck },
    { id: 'settings', label: 'Settings', icon: Settings }
  ];

  const handleNav = (id: PageId) => {
    onNavigate(id);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 bg-slate-950/80 backdrop-blur-xs z-40 md:hidden"
          onClick={onCloseMobile}
        />
      )}

      <aside
        className={`fixed md:static inset-y-0 left-0 z-50 w-60 bg-[#070d1e] border-r border-slate-800 flex flex-col justify-between shrink-0 transition-transform duration-200 ease-in-out ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <div>
          {/* Brand header */}
          <div className="h-16 flex items-center justify-between px-5 border-b border-slate-800/80">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded bg-cyan-950/60 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                <Shield className="w-4 h-4" />
              </div>
              <div className="flex flex-col">
                <span className="text-sm font-semibold tracking-tight text-white font-sans">
                  ThreatLens
                </span>
                <span className="text-[10px] text-slate-400 font-mono tracking-wider">
                  Zero-Day Detection
                </span>
              </div>
            </div>

            <button
              onClick={onCloseMobile}
              className="p-1 text-slate-400 hover:text-white md:hidden"
              aria-label="Close navigation"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Items */}
          <nav className="p-3 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentPage === item.id;

              return (
                <button
                  key={item.id}
                  onClick={() => handleNav(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-[#0f1b3b] text-cyan-400 border border-cyan-500/25 shadow-xs'
                      : 'text-slate-300 hover:text-white hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>

                  <div className="flex items-center gap-1.5">
                    {item.id === 'live_monitoring' && isMonitoringActive && (
                      <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" title="Live Capture Active" />
                    )}
                    {typeof item.count === 'number' && item.count > 0 && (
                      <span className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-rose-950/80 text-rose-300 border border-rose-800/40 tabular-nums">
                        {item.count}
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Minimal system status footer */}
        <div className="p-4 border-t border-slate-800/80">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Monitoring</span>
            <span className={isMonitoringActive ? 'text-cyan-400 font-medium' : 'text-slate-500'}>
              {isMonitoringActive ? 'Active' : 'Inactive'}
            </span>
          </div>
        </div>
      </aside>
    </>
  );
};
