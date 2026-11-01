import React, { useState, useEffect, useCallback } from 'react';
import { TabId } from '../types';

interface GraphViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

export const GraphView: React.FC<GraphViewProps> = ({ onNavigate, showToast }) => {
  const [source, setSource] = useState('');
  const [target, setTarget] = useState('');
  const [calculating, setCalculating] = useState(false);
  const [paths, setPaths] = useState<any[]>([]);
  const [selectedPath, setSelectedPath] = useState<any | null>(null);
  const [graphNodes, setGraphNodes] = useState<any[]>([]);
  const [graphEdges, setGraphEdges] = useState<any[]>([]);
  const [selectedNode, setSelectedNode] = useState<{ id: string; type: string; risk: number; desc: string } | null>(null);

  const [aiPathModalOpen, setAiPathModalOpen] = useState(false);
  const [aiPathExplanation, setAiPathExplanation] = useState<string | null>(null);
  const [explainingPath, setExplainingPath] = useState(false);
  const [aiProviderUsed, setAiProviderUsed] = useState<string | null>(null);

  const loadGraphData = useCallback(async () => {
    setCalculating(true);
    try {
      const graphRes = await fetch('/api/graph/latest');
      if (graphRes.ok) {
        const graphData = await graphRes.json();
        if (graphData.graph && graphData.graph.nodes) {
          setGraphNodes(graphData.graph.nodes);
          setGraphEdges(graphData.graph.edges || []);
          
          // Seed source / target if not set
          const rootNode = graphData.graph.nodes.find((n: any) => n.type === 'domain' || n.type === 'root');
          if (rootNode && !source) {
            setSource(rootNode.id);
          }
        }
      }

      // Fetch prioritized candidate attack paths
      const pathsRes = await fetch('/api/graph/latest/paths');
      if (pathsRes.ok) {
        const pData = await pathsRes.json();
        if (pData.paths && Array.isArray(pData.paths) && pData.paths.length > 0) {
          setPaths(pData.paths);
          setSelectedPath(pData.paths[0]);
          if (!source && pData.paths[0].source_node) setSource(pData.paths[0].source_node);
          if (!target && pData.paths[0].target_node) setTarget(pData.paths[0].target_node);
        } else {
          setPaths([]);
          setSelectedPath(null);
        }
      }
    } catch {
      // Graceful fallback: live zero-state
      setPaths([]);
      setSelectedPath(null);
    } finally {
      setCalculating(false);
    }
  }, [source, target]);

  useEffect(() => {
    loadGraphData();
  }, []);

  const triggerCompute = async () => {
    setCalculating(true);
    try {
      const queryParams = new URLSearchParams();
      if (source.trim()) queryParams.set('source', source.trim());
      if (target.trim()) queryParams.set('target', target.trim());
      
      const res = await fetch(`/api/graph/latest/paths?${queryParams.toString()}`);
      if (res.ok) {
        const data = await res.json();
        if (data.paths && data.paths.length > 0) {
          setPaths(data.paths);
          setSelectedPath(data.paths[0]);
          if (showToast) showToast('success', 'Attack Vector Computed', `Discovered ${data.paths.length} traversable paths`);
        } else {
          setPaths([]);
          setSelectedPath(null);
          if (showToast) showToast('info', 'No Path Traversed', 'No viable attack path discovered between selected nodes.');
        }
      }
    } catch {
      if (showToast) showToast('error', 'Path Computation Failed', 'Unable to traverse topological attack graph.');
    } finally {
      setCalculating(false);
    }
  };

  const explainAttackPathWithAi = async () => {
    if (!selectedPath) return;
    setAiPathModalOpen(true);
    setExplainingPath(true);
    setAiPathExplanation(null);
    try {
      const res = await fetch('/api/llm/explain-path', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          source_node: selectedPath.source_node || source,
          target_node: selectedPath.target_node || target,
          path_nodes: selectedPath.path_nodes || selectedPath.nodes || [],
          cumulative_cost: selectedPath.cumulative_cost || selectedPath.risk_score || 0,
          assumptions: [
            'Attacker has network line-of-sight to perimeter service',
            'Internal network egress between DMZ and database is unsegmented',
            'Service banners expose actionable unpatched vulnerabilities',
          ],
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiPathExplanation(data.explanation || data.narrative || 'Attack path explanation synthesized.');
        setAiProviderUsed(data.provider || 'AI Engine');
        if (showToast) showToast('success', 'Attack Path Synthesized', `Generated via ${data.provider}`);
      } else {
        throw new Error('API Error');
      }
    } catch {
      setAiPathExplanation(
        `### CANDIDATE ATTACK PATH NARRATIVE (${selectedPath.source_node || source} → ${selectedPath.target_node || target})\n\n` +
        `**1. Ingress Vector:**\n` +
        `Adversary discovers external entry point at \`${selectedPath.source_node || source}\` and traverses hops: ${(selectedPath.path_nodes || []).join(' → ')}.\n\n` +
        `**2. Exploitation & Lateral Movement:**\n` +
        `Exploiting the perimeter service allows the adversary to pivot laterally past edge firewall controls directly to ${selectedPath.target_node || target} (Cumulative Risk: ${selectedPath.cumulative_cost || selectedPath.risk_score || 'N/A'}).\n\n` +
        `**3. Defensive Mitigation:**\n` +
        `Apply host micro-segmentation and revoke transit routing between edge gateways and ${selectedPath.target_node || target}.`
      );
      setAiProviderUsed('OFFLINE_SYNTHETIC');
      if (showToast) showToast('info', 'Deterministic Engine', 'Generated heuristic traversal narrative.');
    } finally {
      setExplainingPath(false);
    }
  };

  return (
    <div className="flex-1 overflow-y-auto p-6 lg:p-8 bg-[#F4F1FF] text-[#22213A]">
      <div className="max-w-[1400px] mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[20px] text-[#6C4CF1]">hub</span>
              <h1 className="text-2xl font-bold tracking-tight text-[#22213A]">
                Attack Graph & Risk Topology
              </h1>
            </div>
            <p className="text-sm text-[#77758E] mt-1">
              Topological risk traversal mapping adversary perimeter ingress to high-value assets and databases.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={explainAttackPathWithAi}
              disabled={explainingPath || !selectedPath}
              className="bg-white border border-[#E8E4F2] hover:border-[#6C4CF1]/40 text-[#22213A] px-4 py-2 rounded-xl text-xs font-semibold shadow-sm flex items-center gap-2 transition-all disabled:opacity-40"
            >
              <span className="material-symbols-outlined text-[16px] text-[#6C4CF1]">psychology</span>
              <span>{explainingPath ? 'Synthesizing...' : 'AI Attack Narrative'}</span>
            </button>
            <button
              onClick={loadGraphData}
              className="bg-white border border-[#E8E4F2] hover:border-[#6C4CF1]/40 text-[#22213A] px-4 py-2 rounded-xl text-xs font-semibold shadow-sm flex items-center gap-2 transition-all"
            >
              <span className="material-symbols-outlined text-[16px] text-[#6C4CF1]">sync</span>
              <span>Refresh Topology</span>
            </button>
          </div>
        </div>

        {/* Pathfinder Parameters */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4F2]">
            <span className="text-xs font-bold text-[#22213A] uppercase tracking-wider">
              Network Traversal Coordinates
            </span>
            <span className="text-xs text-[#77758E]">
              Algorithm: Dijkstra Shortest Weighted Vector
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider block mb-1.5">
                Ingress Origin Node
              </label>
              <input
                type="text"
                placeholder="e.g. scanme.nmap.org"
                value={source}
                onChange={(e) => setSource(e.target.value)}
                className="w-full px-4 py-2 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-[#22213A] text-sm focus:border-[#6C4CF1] outline-none"
              />
            </div>
            <div>
              <label className="text-[11px] font-bold text-[#77758E] uppercase tracking-wider block mb-1.5">
                Crown Jewel Objective Node
              </label>
              <input
                type="text"
                placeholder="e.g. CoreDB or InternalAuth"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="w-full px-4 py-2 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-[#22213A] text-sm focus:border-[#6C4CF1] outline-none"
              />
            </div>
          </div>

          <button
            onClick={triggerCompute}
            disabled={calculating}
            className="w-full py-2.5 rounded-xl bg-[#6C4CF1] hover:bg-[#5940D8] text-white font-semibold text-xs tracking-wide transition-all shadow-sm flex items-center justify-center gap-2 active:scale-95 disabled:opacity-50"
          >
            <span className="material-symbols-outlined text-[16px]">alt_route</span>
            <span>{calculating ? 'Calculating Vectors...' : 'Compute Shortest Attack Path'}</span>
          </button>
        </div>

        {/* Path Results & Topology Hops */}
        <div className="bg-white rounded-2xl border border-[#E8E4F2] p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E8E4F2]">
            <span className="text-xs font-bold text-[#22213A] uppercase tracking-wider">
              Traversed Topology Vector
            </span>
            <div className="flex items-center gap-4 text-xs text-[#77758E]">
              <span>Graph Size: <strong className="text-[#22213A]">{graphNodes.length} nodes, {graphEdges.length} edges</strong></span>
              {selectedPath && (
                <span>Cumulative Cost: <strong className="text-[#DC4655]">{selectedPath.cumulative_cost || selectedPath.risk_score || '0.0'}</strong></span>
              )}
            </div>
          </div>

          {selectedPath && selectedPath.path_nodes && selectedPath.path_nodes.length > 0 ? (
            <div className="space-y-4 pt-2">
              <div className="flex flex-wrap items-center gap-2">
                {selectedPath.path_nodes.map((node: string, idx: number) => {
                  const isVuln = node.toLowerCase().includes('cve') || node.toLowerCase().includes('vuln');
                  const isCrown = node.toLowerCase().includes('db') || node.toLowerCase().includes('target');
                  return (
                    <React.Fragment key={idx}>
                      <div
                        onClick={() => setSelectedNode({
                          id: node,
                          type: isVuln ? 'Critical Vulnerability' : isCrown ? 'Crown Jewel' : 'Perimeter Gateway',
                          risk: isVuln ? 9.8 : 4.5,
                          desc: `Graph node traversed during Dijkstra simulation from ${source || selectedPath.source_node} to ${target || selectedPath.target_node}.`,
                        })}
                        className={`px-3.5 py-2 rounded-xl text-xs font-semibold border transition-all cursor-pointer ${
                          isVuln
                            ? 'bg-[#FFF0F1] border-[#DC4655]/30 text-[#DC4655]'
                            : isCrown
                            ? 'bg-[#EAF8F1] border-[#299B75]/30 text-[#299B75]'
                            : 'bg-[#FAF9FF] border-[#E8E4F2] text-[#22213A] hover:border-[#6C4CF1]'
                        }`}
                      >
                        {node}
                      </div>
                      {idx < selectedPath.path_nodes.length - 1 && (
                        <span className="material-symbols-outlined text-[#9896AA] text-[16px]">
                          arrow_forward
                        </span>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>

              {paths.length > 1 && (
                <div className="pt-3 border-t border-[#E8E4F2] flex items-center gap-2">
                  <span className="text-xs text-[#77758E] font-medium">Alternative Paths:</span>
                  {paths.map((p, idx) => (
                    <button
                      key={idx}
                      onClick={() => setSelectedPath(p)}
                      className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-all ${
                        selectedPath === p
                          ? 'bg-[#6C4CF1] text-white'
                          : 'bg-[#FAF9FF] text-[#77758E] border border-[#E8E4F2] hover:text-[#22213A]'
                      }`}
                    >
                      Path #{idx + 1} ({p.path_nodes ? p.path_nodes.length : 0} hops)
                    </button>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="py-16 text-center space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-[#F4F1FF] flex items-center justify-center mx-auto text-[#6C4CF1]">
                <span className="material-symbols-outlined text-2xl">hub</span>
              </div>
              <div>
                <h4 className="text-sm font-bold text-[#22213A]">No Attack Paths Synthesized</h4>
                <p className="text-xs text-[#77758E] max-w-md mx-auto mt-1">
                  Attack paths require active scan telemetry and correlated vulnerability findings. Launch an assessment from AutoRecon to map topological attack graphs.
                </p>
              </div>
            </div>
          )}

          {selectedNode && (
            <div className="mt-4 p-4 rounded-xl bg-[#FAF9FF] border border-[#6C4CF1]/20 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-[#22213A]">{selectedNode.id}</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-[#F3F0FF] text-[#6C4CF1] border border-[#6C4CF1]/20">
                  {selectedNode.type} // Score: {selectedNode.risk}
                </span>
              </div>
              <p className="text-xs text-[#77758E] leading-relaxed">
                {selectedNode.desc}
              </p>
              {selectedNode.type.includes('Vulnerability') && (
                <div className="flex items-center gap-2 mt-2 pt-2 border-t border-purple-100/80">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-[#FFF0F1] text-[#DC4655] border border-[#DC4655]/30 flex items-center gap-1 animate-pulse">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#DC4655]"></span>
                    <span>⚡ METASPLOIT WEAPONIZED (0.4x Traversal Cost)</span>
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">Dijkstra Priority Vector</span>
                </div>
              )}
            </div>
          )}
        </div>

      </div>

      {/* AI Explanation Modal */}
      {aiPathModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl border border-[#E8E4F2] shadow-2xl max-w-2xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#E8E4F2]">
              <h3 className="text-sm font-bold text-[#22213A] uppercase tracking-wider">
                AI Attack Vector Simulation
              </h3>
              <button
                onClick={() => setAiPathModalOpen(false)}
                className="w-8 h-8 rounded-lg bg-[#FAF9FF] hover:bg-[#F4F1FF] text-[#77758E] flex items-center justify-center"
              >
                <span className="material-symbols-outlined text-[16px]">close</span>
              </button>
            </div>

            <div className="p-4 rounded-xl bg-[#FAF9FF] border border-[#E8E4F2] text-xs text-[#22213A] whitespace-pre-wrap leading-relaxed max-h-[360px] overflow-y-auto">
              {explainingPath ? (
                <div className="flex items-center gap-2 text-[#6C4CF1]">
                  <span className="material-symbols-outlined animate-spin text-[18px]">progress_activity</span>
                  <span>Synthesizing topological attack path narrative...</span>
                </div>
              ) : (
                aiPathExplanation
              )}
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-xs text-[#77758E]">
                Engine: {aiProviderUsed || 'DRISHTI Deterministic Graph Engine'}
              </span>
              <button
                onClick={() => setAiPathModalOpen(false)}
                className="px-4 py-2 rounded-xl bg-[#6C4CF1] hover:bg-[#5940D8] text-white text-xs font-semibold shadow-sm"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
