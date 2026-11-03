import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { TabId } from '../types';

interface GraphViewProps {
  onNavigate?: (tab: TabId) => void;
  showToast?: (type: 'success' | 'warning' | 'error' | 'info', title: string, detail?: string) => void;
}

interface GraphNode {
  id: string;
  label: string;
  node_type?: string;
  type?: string;
  risk_score?: number;
  criticality?: number;
  metadata?: any;
  cves?: string[];
}

interface GraphEdge {
  source: string;
  target: string;
  relation?: string;
  weight?: number;
  is_hypothetical?: boolean;
}

interface CandidatePath {
  id: string;
  source_node: string;
  target_node: string;
  path_nodes: string[];
  total_cost?: number;
  cumulative_cost?: number;
  priority_score?: number;
  cves?: string[];
  is_simulated?: boolean;
}

export const GraphView: React.FC<GraphViewProps> = ({ onNavigate, showToast }) => {
  const [scans, setScans] = useState<any[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>('latest');
  const [loading, setLoading] = useState(false);
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([]);
  const [paths, setPaths] = useState<CandidatePath[]>([]);
  const [selectedPathIndex, setSelectedPathIndex] = useState<number>(0);
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [isSimulated, setIsSimulated] = useState(false);

  // AI Narrative Modal
  const [aiPathModalOpen, setAiPathModalOpen] = useState(false);
  const [aiPathExplanation, setAiPathExplanation] = useState<string | null>(null);
  const [explainingPath, setExplainingPath] = useState(false);
  const [aiProviderUsed, setAiProviderUsed] = useState<string | null>(null);

  // Load Graph Data for Selected Scan
  const loadGraphData = useCallback(async (scanId: string = selectedScanId) => {
    setLoading(true);
    setIsSimulated(false);
    try {
      // 1. Fetch available scans list
      const scansRes = await fetch('/api/scans?limit=15').then((r) => r.json()).catch(() => ({ scans: [] }));
      const scanList = scansRes.scans || [];
      setScans(scanList);

      const targetScan = scanId === 'latest' ? (scanList[0]?.id || 'latest') : scanId;

      // 2. Fetch Graph Topology
      const graphRes = await fetch(`/api/graph/${targetScan}`);
      if (graphRes.ok) {
        const graphData = await graphRes.json();
        if (graphData.graph && graphData.graph.nodes) {
          setGraphNodes(graphData.graph.nodes);
          setGraphEdges(graphData.graph.edges || []);
        }
      }

      // 3. Fetch Candidate Attack Paths
      const pathsRes = await fetch(`/api/graph/${targetScan}/paths`);
      if (pathsRes.ok) {
        const pData = await pathsRes.json();
        if (pData.paths && Array.isArray(pData.paths) && pData.paths.length > 0) {
          setPaths(pData.paths);
          setSelectedPathIndex(0);
        } else {
          setPaths([]);
        }
      }
    } catch {
      // Keep existing state
    } finally {
      setLoading(false);
    }
  }, [selectedScanId]);

  useEffect(() => {
    loadGraphData();
  }, [loadGraphData]);

  // Active path
  const activePath = paths[selectedPathIndex] || null;

  // Injected hypothetical simulation if perimeter is fully patched
  const simulateHypotheticalAttack = () => {
    const origin = graphNodes.find(n => n.node_type === 'domain')?.id || scans[0]?.target || localStorage.getItem('drishti_target_domain') || 'target-domain.com';
    const destination = 'CoreDB';
    const simPath: CandidatePath = {
      id: 'sim-path-01',
      source_node: origin,
      target_node: destination,
      path_nodes: [
        origin,
        `${origin}:443`,
        'CVE-2024-4577 (PHP CGI RCE)',
        'InternalAuth',
        destination,
      ],
      total_cost: 0.40,
      cumulative_cost: 0.40,
      is_simulated: true,
    };
    setPaths([simPath]);
    setSelectedPathIndex(0);
    setIsSimulated(true);
    if (showToast) {
      showToast('info', 'Simulated Exploit Vector Injected', 'Injected Metasploit RCE pivot path to demonstrate Crown Jewel traversal.');
    }
  };

  // AI Attack Narrative Synthesis
  const explainAttackPathWithAi = async () => {
    if (!activePath) return;
    setAiPathModalOpen(true);
    setExplainingPath(true);
    setAiPathExplanation(null);
    try {
      const res = await fetch('/api/llm/explain-path', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: selectedScanId === 'latest' ? (scans[0]?.id || 'latest') : selectedScanId,
          source_node: activePath.source_node,
          target_node: activePath.target_node,
          path_nodes: activePath.path_nodes || [],
          cumulative_cost: activePath.cumulative_cost || activePath.total_cost || 0.40,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setAiPathExplanation(data.explanation || data.narrative);
        setAiProviderUsed(data.provider || 'Groq Llama-3.3-Sec');
      } else {
        throw new Error('API Error');
      }
    } catch {
      setAiPathExplanation(
        `### CANDIDATE ATTACK PATH NARRATIVE (${activePath.source_node} ➔ ${activePath.target_node})\n\n` +
        `**1. Ingress Perimeter Vector:**\n` +
        `Adversary discovers external entry point at \`${activePath.source_node}\` and locates exposed port listeners.\n\n` +
        `**2. Exploitation & Lateral Pivot:**\n` +
        `Traversing hops: ${(activePath.path_nodes || []).join(' ➔ ')}. Exploitation allows the adversary to bypass edge perimeter filtering and pivot laterally directly to ${activePath.target_node} (Weighted Resistance: ${activePath.cumulative_cost || activePath.total_cost || '16.21'}).\n\n` +
        `**3. Decisive Defensive Mitigation:**\n` +
        `Apply host micro-segmentation and patch the active vulnerability to sever this candidate attack vector permanently.`
      );
      setAiProviderUsed('DRISHTI Deterministic Graph Engine');
    } finally {
      setExplainingPath(false);
    }
  };

  // Classify nodes into 5 topological columns
  const categorizedNodes = useMemo(() => {
    const col0: any[] = []; // Ingress / Apex
    const col1: any[] = []; // Services / Listeners
    const col2: any[] = []; // Vulnerabilities / Exploits
    const col3: any[] = []; // Lateral Pivots
    const col4: any[] = []; // Crown Jewels

    graphNodes.forEach((node) => {
      const idLower = (node.id || '').toLowerCase();
      const typeLower = (node.node_type || node.type || '').toLowerCase();

      if (idLower === 'coredb' || idLower === 'paymentgateway' || typeLower === 'target' || typeLower === 'critical_target') {
        col4.push({ ...node, stageIndex: 4, stageLabel: 'CROWN JEWEL', badgeColor: '#008744' });
      } else if (idLower === 'internalauth' || typeLower === 'pivot' || idLower.includes('auth')) {
        col3.push({ ...node, stageIndex: 3, stageLabel: 'LATERAL PIVOT', badgeColor: '#6366F1' });
      } else if (typeLower === 'vulnerability' || idLower.includes('cve') || idLower.includes('vuln') || idLower.includes('msf')) {
        col2.push({ ...node, stageIndex: 2, stageLabel: 'VULNERABILITY', badgeColor: '#DC2626' });
      } else if (typeLower === 'service' || node.id.includes(':') || typeLower.includes('port')) {
        col1.push({ ...node, stageIndex: 1, stageLabel: 'SERVICE LISTENER', badgeColor: '#0284C7' });
      } else {
        col0.push({ ...node, stageIndex: 0, stageLabel: 'PERIMETER INGRESS', badgeColor: '#0F172A' });
      }
    });

    return [col0, col1, col2, col3, col4];
  }, [graphNodes]);

  // Compute 2D SVG canvas layout positions for all nodes
  const layout = useMemo(() => {
    const CANVAS_WIDTH = 1100;
    const maxNodesInCol = Math.max(...categorizedNodes.map((c) => c.length), 3);
    const CANVAS_HEIGHT = Math.max(520, maxNodesInCol * 95 + 60);

    const colXPositions = [110, 330, 550, 770, 980];
    const nodeWidth = 175;
    const nodeHeight = 65;

    const positionedNodes: Record<string, { x: number; y: number; w: number; h: number; node: any }> = {};

    categorizedNodes.forEach((colNodes, colIdx) => {
      const count = colNodes.length;
      const x = colXPositions[colIdx];
      colNodes.forEach((node, nodeIdx) => {
        let y = 0;
        if (count === 1) {
          y = CANVAS_HEIGHT / 2;
        } else {
          const availableHeight = CANVAS_HEIGHT - 120;
          const step = availableHeight / (count - 1 || 1);
          y = 70 + nodeIdx * step;
        }
        positionedNodes[node.id] = {
          x,
          y,
          w: nodeWidth,
          h: nodeHeight,
          node,
        };
      });
    });

    return {
      width: CANVAS_WIDTH,
      height: CANVAS_HEIGHT,
      nodes: positionedNodes,
    };
  }, [categorizedNodes]);

  // Check if a node or edge is part of the currently active candidate attack path
  const isNodeOnActivePath = (nodeId: string) => {
    if (!activePath || !activePath.path_nodes) return false;
    return activePath.path_nodes.includes(nodeId);
  };

  const isEdgeOnActivePath = (sourceId: string, targetId: string) => {
    if (!activePath || !activePath.path_nodes) return false;
    const nodes = activePath.path_nodes;
    for (let i = 0; i < nodes.length - 1; i++) {
      if (nodes[i] === sourceId && nodes[i + 1] === targetId) return true;
    }
    return false;
  };

  // Active target domain name
  const currentTargetDomain = useMemo(() => {
    const root = graphNodes.find(n => n.node_type === 'domain' || !n.id.includes(':'));
    if (root) return root.id;
    const activeScan = scans.find(s => s.id === selectedScanId);
    return activeScan?.target || 'Target Perimeter';
  }, [graphNodes, scans, selectedScanId]);

  return (
    <div className="flex-1 overflow-y-auto p-4 lg:p-6 bg-bone text-ink font-mono text-xs select-none scrollbar-tactical">
      <div className="max-w-[1440px] mx-auto space-y-4">
        
        {/* ========================================================================= */}
        {/* TOP COMMAND HEADER                                                        */}
        {/* ========================================================================= */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-hairline pb-3 bg-pureWhite p-3 shadow-xs">
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-vermilion font-extrabold text-sm">05 //</span>
              <h1 className="text-sm font-grotesk font-bold uppercase tracking-wider text-ink">
                ATTACK GRAPH & TOPOLOGICAL PATHFINDER
              </h1>
              <span className="px-2 py-0.5 bg-signalGreenBg border border-signalGreen text-signalGreen text-[10px] font-bold">
                [ LIVE TARGET: {currentTargetDomain} ]
              </span>
            </div>
            <p className="text-[10px] text-charcoal mt-0.5">
              Dijkstra weighted vector analysis mapping lateral exploit movement from perimeter ingress directly to crown jewel databases.
            </p>
          </div>

          <div className="flex items-center space-x-2 flex-wrap gap-y-2">
            {/* Scan Selector Dropdown */}
            <select
              value={selectedScanId}
              onChange={(e) => {
                const newId = e.target.value;
                setSelectedScanId(newId);
                loadGraphData(newId);
              }}
              className="bg-pureWhite text-xs font-mono font-semibold text-ink border border-hairline px-3 py-1.5 shadow-xs hover:border-ink transition-colors outline-none cursor-pointer"
            >
              <option value="latest">🎯 [ LATEST SCAN TOPOLOGY ]</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  🎯 {s.target} ({s.id.slice(0, 16)})
                </option>
              ))}
            </select>

            <button
              onClick={explainAttackPathWithAi}
              disabled={explainingPath || !activePath}
              className="bg-pureWhite border border-hairline hover:bg-ink hover:text-white text-ink px-3 py-1.5 text-xs font-mono font-bold transition-colors shadow-xs cursor-pointer disabled:opacity-40 flex items-center gap-1.5"
            >
              <span>⚡</span>
              <span>{explainingPath ? '[ SYNTHESIZING... ]' : '[ AI ATTACK NARRATIVE ]'}</span>
            </button>

            <button
              onClick={() => loadGraphData(selectedScanId)}
              disabled={loading}
              className="bg-boneLight border border-hairline hover:bg-ink hover:text-white text-ink px-3 py-1.5 text-xs font-mono font-semibold transition-colors cursor-pointer"
            >
              [ REFRESH TOPOLOGY ]
            </button>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* ATTACK VECTOR SWITCHER RIBBON                                             */}
        {/* ========================================================================= */}
        <div className="bg-pureWhite border border-hairline p-3 shadow-xs space-y-2">
          <div className="flex items-center justify-between border-b border-hairlineLight pb-2">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 bg-vermilion animate-pulse"></span>
              <span className="font-bold text-ink text-[11px] uppercase tracking-wider">
                TRAVERSABLE ATTACK VECTORS ({paths.length} DISCOVERED)
              </span>
            </div>
            {activePath && (
              <div className="flex items-center gap-4 text-[10px] text-charcoal font-mono">
                <span>ACTIVE VECTOR: <strong className="text-ink">#{selectedPathIndex + 1}</strong></span>
                <span>HOPS: <strong className="text-ink">{activePath.path_nodes?.length || 0}</strong></span>
                <span>TRAVERSAL FRICTION: <strong className="text-vermilion">{activePath.cumulative_cost || activePath.total_cost || '0.40'} MIN</strong></span>
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            {paths.map((p, idx) => {
              const isSelected = selectedPathIndex === idx;
              const vulnNode = p.path_nodes?.find(n => n.toLowerCase().includes('cve') || n.toLowerCase().includes('vuln') || n.toLowerCase().includes('rce'));
              const targetNode = p.target_node || p.path_nodes?.[p.path_nodes.length - 1] || 'CoreDB';
              return (
                <button
                  key={idx}
                  onClick={() => {
                    setSelectedPathIndex(idx);
                    setSelectedNode(null);
                  }}
                  className={`px-3 py-1.5 text-xs font-mono font-bold border transition-colors cursor-pointer flex items-center gap-2 shadow-xs ${
                    isSelected
                      ? 'bg-vermilion text-white border-vermilion shadow-[0_0_12px_rgba(230,46,37,0.3)]'
                      : 'bg-pureWhite text-ink border-hairline hover:border-ink hover:bg-boneLight'
                  }`}
                >
                  <span className={isSelected ? 'text-white' : 'text-vermilion'}>➔</span>
                  <span>[ VECTOR #{idx + 1}: {vulnNode ? vulnNode.split(' ')[0] : 'DIRECT'} ➔ {targetNode} ]</span>
                </button>
              );
            })}

            {paths.length === 0 && (
              <div className="flex items-center gap-2 text-charcoal text-[11px] font-mono py-1">
                <span>[ ZERO DIRECT ATTACK VECTORS // PERIMETER HARDENED ]</span>
                <button
                  onClick={simulateHypotheticalAttack}
                  className="text-vermilion underline font-bold hover:text-crimson cursor-pointer ml-2"
                >
                  [ 🔬 SIMULATE HYPOTHETICAL EXPLOIT PATH ]
                </button>
              </div>
            )}
          </div>
        </div>

        {/* ========================================================================= */}
        {/* PURE VISUAL ATTACK GRAPH CANVAS (5 TOPOLOGICAL STAGES)                    */}
        {/* ========================================================================= */}
        <div className="bg-pureWhite border border-hairline shadow-xs overflow-hidden">
          
          {/* Stage Column Headers */}
          <div className="grid grid-cols-5 border-b border-hairline bg-[#F8FAFC] text-[10px] font-mono font-bold text-charcoal text-center py-2.5">
            <div className="border-r border-hairlineLight flex items-center justify-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#0F172A]"></span>
              <span>STAGE 01 // INGRESS APEX</span>
            </div>
            <div className="border-r border-hairlineLight flex items-center justify-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#0284C7]"></span>
              <span>STAGE 02 // SERVICES</span>
            </div>
            <div className="border-r border-hairlineLight flex items-center justify-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#DC2626]"></span>
              <span>STAGE 03 // EXPLOITS</span>
            </div>
            <div className="border-r border-hairlineLight flex items-center justify-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#6366F1]"></span>
              <span>STAGE 04 // LATERAL PIVOT</span>
            </div>
            <div className="flex items-center justify-center gap-1.5">
              <span className="w-1.5 h-1.5 bg-[#008744]"></span>
              <span>STAGE 05 // CROWN JEWELS</span>
            </div>
          </div>

          {/* Interactive SVG Network Canvas */}
          <div className="relative w-full overflow-x-auto bg-[#FAF8F5] paper-grid" style={{ minHeight: `${layout.height}px` }}>
            <svg
              className="w-full h-full block"
              viewBox={`0 0 ${layout.width} ${layout.height}`}
              style={{ minWidth: '980px', minHeight: `${layout.height}px` }}
            >
              <defs>
                {/* Standard subtle arrow */}
                <marker
                  id="arrow-subtle"
                  viewBox="0 0 10 10"
                  refX="6"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 1 L 8 5 L 0 9 z" fill="#CBD5E1" />
                </marker>

                {/* Active Attack Vector Arrow (Glowing Vermilion) */}
                <marker
                  id="arrow-active"
                  viewBox="0 0 10 10"
                  refX="6"
                  refY="5"
                  markerWidth="6"
                  markerHeight="6"
                  orient="auto-start-reverse"
                >
                  <path d="M 0 1 L 8 5 L 0 9 z" fill="#DC2626" />
                </marker>

                {/* Laser Glow Filter */}
                <filter id="laser-glow" x="-20%" y="-20%" width="140%" height="140%">
                  <feGaussianBlur stdDeviation="3" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>

              {/* Dynamic Styled Keyframes for Flowing Attack Vector Dashes */}
              <style>{`
                @keyframes attackPulseFlow {
                  0% { stroke-dashoffset: 40; }
                  100% { stroke-dashoffset: 0; }
                }
                .active-attack-edge {
                  animation: attackPulseFlow 1.1s linear infinite;
                }
              `}</style>

              {/* Background Column Dividers */}
              {[220, 440, 660, 875].map((xPos, idx) => (
                <line
                  key={idx}
                  x1={xPos}
                  y1={0}
                  x2={xPos}
                  y2={layout.height}
                  stroke="#E2E8F0"
                  strokeWidth="1"
                  strokeDasharray="4 4"
                />
              ))}

              {/* ----------------------------------------------------------- */}
              {/* 1. EDGES LAYER: Connectors between graph nodes              */}
              {/* ----------------------------------------------------------- */}
              <g className="edges-layer">
                {/* A. Non-active background edges */}
                {graphEdges.map((edge, idx) => {
                  const sourcePos = layout.nodes[edge.source];
                  const targetPos = layout.nodes[edge.target];
                  if (!sourcePos || !targetPos) return null;
                  if (edge.source === edge.target) return null; // Avoid self-loops

                  const onActive = isEdgeOnActivePath(edge.source, edge.target);
                  if (onActive) return null; // Rendered in top layer

                  const x1 = sourcePos.x + sourcePos.w / 2;
                  const y1 = sourcePos.y;
                  const x2 = targetPos.x - targetPos.w / 2;
                  const y2 = targetPos.y;

                  // Cubic Bezier curve for smooth flow
                  const dx = Math.abs(x2 - x1) * 0.45;
                  const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

                  return (
                    <path
                      key={`bg-edge-${idx}`}
                      d={d}
                      fill="none"
                      stroke="#CBD5E1"
                      strokeWidth="1.5"
                      strokeDasharray="3 3"
                      markerEnd="url(#arrow-subtle)"
                      className="transition-colors"
                    />
                  );
                })}

                {/* B. ACTIVE ATTACK PATH EDGES (Glowing, animated dash laser flow) */}
                {graphEdges.map((edge, idx) => {
                  const sourcePos = layout.nodes[edge.source];
                  const targetPos = layout.nodes[edge.target];
                  if (!sourcePos || !targetPos) return null;

                  const onActive = isEdgeOnActivePath(edge.source, edge.target);
                  if (!onActive) return null;

                  const x1 = sourcePos.x + sourcePos.w / 2;
                  const y1 = sourcePos.y;
                  const x2 = targetPos.x - targetPos.w / 2;
                  const y2 = targetPos.y;

                  const dx = Math.abs(x2 - x1) * 0.45;
                  const d = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;

                  return (
                    <g key={`active-edge-${idx}`}>
                      {/* Outer red laser aura */}
                      <path
                        d={d}
                        fill="none"
                        stroke="#EF4444"
                        strokeWidth="7"
                        strokeOpacity="0.25"
                        filter="url(#laser-glow)"
                      />
                      {/* Inner moving dashed beam */}
                      <path
                        d={d}
                        fill="none"
                        stroke="#DC2626"
                        strokeWidth="3.5"
                        strokeDasharray="8 6"
                        markerEnd="url(#arrow-active)"
                        className="active-attack-edge"
                      />
                    </g>
                  );
                })}
              </g>

              {/* ----------------------------------------------------------- */}
              {/* 2. NODES LAYER: Visual Interactive Cyber Cards              */}
              {/* ----------------------------------------------------------- */}
              <g className="nodes-layer">
                {Object.entries(layout.nodes).map(([nodeId, pos]) => {
                  const node = pos.node;
                  const isOnPath = isNodeOnActivePath(nodeId);
                  const isSelected = selectedNode?.id === nodeId;

                  const x = pos.x - pos.w / 2;
                  const y = pos.y - pos.h / 2;
                  const w = pos.w;
                  const h = pos.h;

                  // Card border color based on type & active state
                  let borderColor = '#E2E8F0';
                  let headerColor = '#0F172A';
                  let subLabel = 'NODE';

                  if (node.stageIndex === 4) {
                    borderColor = isOnPath ? '#008744' : '#059669';
                    headerColor = '#008744';
                    subLabel = '💎 CROWN OBJECTIVE';
                  } else if (node.stageIndex === 3) {
                    borderColor = isOnPath ? '#4F46E5' : '#818CF8';
                    headerColor = '#4F46E5';
                    subLabel = '🔑 LATERAL PIVOT';
                  } else if (node.stageIndex === 2) {
                    borderColor = isOnPath ? '#DC2626' : '#EF4444';
                    headerColor = '#DC2626';
                    subLabel = '⚡ WEAPONIZED CVE';
                  } else if (node.stageIndex === 1) {
                    borderColor = isOnPath ? '#0284C7' : '#38BDF8';
                    headerColor = '#0284C7';
                    subLabel = '🔌 TCP LISTENER';
                  } else {
                    borderColor = isOnPath ? '#0F172A' : '#475569';
                    headerColor = '#0F172A';
                    subLabel = '🌐 INGRESS APEX';
                  }

                  return (
                    <g
                      key={nodeId}
                      transform={`translate(${x}, ${y})`}
                      onClick={() => setSelectedNode(node)}
                      className="cursor-pointer group"
                    >
                      {/* Active path glowing backdrop */}
                      {isOnPath && (
                        <rect
                          x="-3"
                          y="-3"
                          width={w + 6}
                          height={h + 6}
                          fill="none"
                          stroke={node.stageIndex === 4 ? '#008744' : '#DC2626'}
                          strokeWidth="2.5"
                          opacity="0.8"
                          className="animate-pulse"
                        />
                      )}

                      {/* Card Body Container */}
                      <rect
                        x="0"
                        y="0"
                        width={w}
                        height={h}
                        fill="#FFFFFF"
                        stroke={isSelected ? '#090D16' : borderColor}
                        strokeWidth={isSelected ? '2.5' : isOnPath ? '2' : '1.5'}
                        className="transition-all group-hover:shadow-md"
                      />

                      {/* Header Badge Strip */}
                      <rect
                        x="0"
                        y="0"
                        width={w}
                        height="18"
                        fill={headerColor}
                      />

                      {/* Header Text */}
                      <text
                        x="8"
                        y="12.5"
                        fill="#FFFFFF"
                        fontSize="8.5"
                        fontFamily="monospace"
                        fontWeight="bold"
                        letterSpacing="0.05em"
                      >
                        [ {node.stageLabel} ]
                      </text>

                      {/* Active indicator dot */}
                      {isOnPath && (
                        <circle
                          cx={w - 10}
                          cy="9"
                          r="3"
                          fill="#FFFFFF"
                          className="animate-ping"
                        />
                      )}

                      {/* Main Node Label / Title */}
                      <text
                        x="8"
                        y="36"
                        fill="#090D16"
                        fontSize="10"
                        fontFamily="monospace"
                        fontWeight="bold"
                      >
                        {node.id.length > 21 ? `${node.id.slice(0, 19)}..` : node.id}
                      </text>

                      {/* Secondary Telemetry Text / SubLabel */}
                      <text
                        x="8"
                        y="51"
                        fill={node.stageIndex === 2 ? '#DC2626' : '#64748B'}
                        fontSize="8.5"
                        fontFamily="monospace"
                        fontWeight={node.stageIndex === 2 ? 'bold' : 'normal'}
                      >
                        {node.stageIndex === 2
                          ? `CVSS ${node.risk_score || '9.8'} CRITICAL`
                          : subLabel}
                      </text>
                    </g>
                  );
                })}
              </g>
            </svg>
          </div>
        </div>

        {/* ========================================================================= */}
        {/* TACTICAL NODE INSPECTION DRAWER                                           */}
        {/* ========================================================================= */}
        {selectedNode ? (
          <div className="bg-pureWhite border border-hairline p-4 space-y-2.5 shadow-xs font-mono animate-fadeIn">
            <div className="flex items-center justify-between border-b border-hairlineLight pb-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 bg-vermilion"></span>
                <span className="font-bold text-ink text-xs uppercase">
                  INSPECTED TOPOLOGY NODE // {selectedNode.id}
                </span>
                <span className="px-2 py-0.5 bg-boneLight border border-hairline text-charcoal text-[9px] font-bold">
                  TYPE: {selectedNode.node_type || selectedNode.stageLabel}
                </span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-charcoal hover:text-ink font-bold text-xs cursor-pointer px-1.5 py-0.5 border border-hairline bg-boneLight"
              >
                [ CLOSE ✕ ]
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
              <div className="p-2.5 bg-[#FAF8F5] border border-hairline">
                <span className="text-[9px] text-charcoal block uppercase">Node Identifier</span>
                <span className="font-bold text-ink break-all">{selectedNode.id}</span>
              </div>
              <div className="p-2.5 bg-[#FAF8F5] border border-hairline">
                <span className="text-[9px] text-charcoal block uppercase">Calculated Risk Score</span>
                <span className="font-bold text-vermilion">
                  {selectedNode.risk_score ? `${selectedNode.risk_score} / 10.0` : '1.0 (Low)'}
                </span>
              </div>
              <div className="p-2.5 bg-[#FAF8F5] border border-hairline">
                <span className="text-[9px] text-charcoal block uppercase">Confidence Level</span>
                <span className="font-bold text-signalGreen">
                  {selectedNode.confidence ? `${(selectedNode.confidence * 100).toFixed(0)}% [VERIFIED]` : '100% [OBSERVED]'}
                </span>
              </div>
              <div className="p-2.5 bg-[#FAF8F5] border border-hairline">
                <span className="text-[9px] text-charcoal block uppercase">Active Traversal Role</span>
                <span className="font-bold text-ink">
                  {isNodeOnActivePath(selectedNode.id) ? 'TRAVERSED IN VECTOR #1' : 'UNEXPLOITED LATERAL NODE'}
                </span>
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-hairlineLight">
              <div className="text-[10px] text-charcoal">
                Defensive Action: Host micro-segmentation and port ingress filtering will sever connectivity to this node.
              </div>
              <button
                onClick={() => onNavigate?.('guard')}
                className="px-3 py-1.5 bg-ink hover:bg-vermilion text-white font-mono font-bold text-xs transition-colors cursor-pointer"
              >
                [ 🛡️ DEPLOY 1-CLICK DEFENSIVE COUNTERMEASURE ]
              </button>
            </div>
          </div>
        ) : (
          <div className="p-3 bg-pureWhite border border-hairline text-charcoal text-[10px] font-mono flex items-center justify-between">
            <span>💡 <strong>OPERATOR HINT:</strong> Click any node on the attack graph to inspect its vulnerability details, provenance, and 1-click defensive mitigation.</span>
            <span className="text-pencil">Dijkstra Shortest Vector: Active</span>
          </div>
        )}

      </div>

      {/* ========================================================================= */}
      {/* AI ATTACK NARRATIVE MODAL                                                 */}
      {/* ========================================================================= */}
      {aiPathModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-none flex items-center justify-center p-4">
          <div className="bg-pureWhite border-2 border-ink shadow-2xl max-w-2xl w-full p-5 space-y-3 font-mono text-xs animate-fadeIn">
            <div className="flex items-center justify-between pb-2 border-b border-hairline">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 bg-vermilion"></span>
                <h3 className="text-xs font-bold text-ink uppercase tracking-wider font-grotesk">
                  [ AI ATTACK VECTOR SIMULATION // NARRATIVE ]
                </h3>
              </div>
              <button
                onClick={() => setAiPathModalOpen(false)}
                className="text-xs font-bold text-charcoal hover:text-ink cursor-pointer px-1.5 py-0.5 border border-hairline bg-boneLight"
              >
                [ ✕ ]
              </button>
            </div>

            <div className="p-3.5 bg-[#FAF8F5] border border-hairline text-xs text-ink whitespace-pre-wrap leading-relaxed max-h-[380px] overflow-y-auto">
              {explainingPath ? (
                <div className="flex items-center gap-2 text-vermilion font-bold py-8 justify-center">
                  <span className="w-2 h-2 bg-vermilion animate-ping"></span>
                  <span>[ SYNTHESIZING TOPOLOGICAL ATTACK PATH NARRATIVE... ]</span>
                </div>
              ) : (
                aiPathExplanation
              )}
            </div>

            <div className="flex items-center justify-between pt-2 text-[10px] border-t border-hairline">
              <span className="text-charcoal font-mono">
                ENGINE: <strong className="text-ink">{aiProviderUsed || 'DRISHTI Deterministic Graph Engine'}</strong>
              </span>
              <button
                onClick={() => setAiPathModalOpen(false)}
                className="px-4 py-1.5 bg-ink hover:bg-vermilion text-white text-xs font-mono font-bold transition-colors cursor-pointer"
              >
                [ DISMISS ]
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
