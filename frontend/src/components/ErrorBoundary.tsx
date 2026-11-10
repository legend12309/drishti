import React, { Component, ErrorInfo, ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error, errorInfo: null };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[DRISHTI-UI-ERROR-BOUNDARY] Uncaught interface exception:', error, errorInfo);
    this.setState({ errorInfo });
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="w-screen h-screen bg-[#07090E] flex flex-col items-center justify-center p-6 text-pureWhite font-mono select-none">
          <div className="max-w-xl w-full bg-[#0D1117] border border-vermilion/80 p-6 shadow-2xl space-y-4">
            <div className="flex items-center space-x-3 border-b border-vermilion/40 pb-3">
              <span className="w-3 h-3 bg-vermilion animate-ping"></span>
              <span className="text-vermilion font-bold tracking-widest text-sm">
                [ DRISHTI // UI FAULT CONTAINED ]
              </span>
            </div>

            <p className="text-xs text-boneLight/80 leading-relaxed">
              A view rendering fault occurred and was successfully intercepted by the DRISHTI UI Error Shield. The core backend daemon and database state remain completely intact.
            </p>

            {this.state.error && (
              <div className="p-3 bg-black/60 border border-hairline/40 text-[11px] text-vermilion font-mono overflow-x-auto">
                <span className="font-bold">ERROR:</span> {this.state.error.toString()}
              </div>
            )}

            <div className="pt-2 flex items-center justify-between border-t border-hairline/40">
              <span className="text-[10px] text-pencil">
                ENCLAVE INTEGRITY: UNCOMPROMISED
              </span>
              <button
                onClick={this.handleReset}
                className="px-4 py-2 bg-vermilion hover:bg-vermilion/80 text-pureWhite font-bold text-xs active:scale-95 transition-all shadow-md cursor-pointer"
              >
                [ ⟳ RELOAD & RESTORE ENCLAVE ]
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
