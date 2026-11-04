import React from 'react';

export type DoodleName =
  | 'osint'
  | 'search'
  | 'ingress'
  | 'globe'
  | 'service'
  | 'port'
  | 'exploit'
  | 'vuln'
  | 'spark'
  | 'pivot'
  | 'key'
  | 'crown'
  | 'vault'
  | 'target'
  | 'reticle'
  | 'shield'
  | 'probe'
  | 'rocket'
  | 'check'
  | 'warning'
  | 'alert'
  | 'lock'
  | 'radar'
  | 'gear';

interface DoodleIconProps extends React.SVGProps<SVGSVGElement> {
  name: DoodleName | string;
  size?: number | string;
  className?: string;
}

interface DoodleGroupProps {
  name: DoodleName | string;
  x?: number;
  y?: number;
  size?: number;
  color?: string;
  strokeWidth?: number;
  className?: string;
}

// Render technical drafting doodle paths (viewBox 0 0 24 24)
export const renderDoodlePaths = (name: string, strokeWidth = 1.8) => {
  const norm = name.toLowerCase().trim();

  switch (norm) {
    case 'osint':
    case 'search':
    case 'recon':
      // Technical magnifying reticle with drafting crosshairs & angled grip
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="10" cy="10" r="6" />
          <line x1="10" y1="7" x2="10" y2="13" strokeDasharray="1.2 1.2" opacity="0.85" />
          <line x1="7" y1="10" x2="13" y2="10" strokeDasharray="1.2 1.2" opacity="0.85" />
          <circle cx="10" cy="10" r="1" fill="currentColor" stroke="none" />
          <path d="M14.5 14.5L20.5 20.5" />
          <line x1="17" y1="19" x2="19" y2="17" strokeWidth={strokeWidth * 0.9} />
        </g>
      );

    case 'ingress':
    case 'globe':
    case 'network':
    case 'apex':
      // Technical perimeter globe with latitude/longitude drafting rings & apex cross-axis
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="8.5" />
          <ellipse cx="12" cy="12" rx="8.5" ry="3.2" />
          <path d="M12 3.5c-2.4 2.4 -2.4 14.6 0 17" />
          <path d="M12 3.5c2.4 2.4 2.4 14.6 0 17" />
          <line x1="12" y1="1" x2="12" y2="3.5" strokeWidth="2" />
          <line x1="12" y1="20.5" x2="12" y2="23" strokeWidth="2" />
        </g>
      );

    case 'service':
    case 'port':
    case 'listener':
    case 'daemon':
      // Technical network socket / interface daemon port with RJ45 connector pins
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <rect x="4.5" y="5.5" width="15" height="13" rx="2" />
          <path d="M8 5.5V9M10.5 5.5V9M13.5 5.5V9M16 5.5V9" strokeWidth={strokeWidth * 0.9} />
          <path d="M8 18.5v2a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-2" />
          <circle cx="7.5" cy="14" r="1" fill="currentColor" stroke="none" />
        </g>
      );

    case 'exploit':
    case 'vuln':
    case 'spark':
    case 'weaponized':
    case 'zap':
      // Angular high-voltage exploit breach vector doodle
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M13 2.5L4.5 13.5h6l-2 8 11-12h-6.5l2-7z" fill="currentColor" fillOpacity="0.12" />
          <circle cx="13" cy="2.5" r="0.8" fill="currentColor" stroke="none" />
          <circle cx="8.5" cy="21.5" r="0.8" fill="currentColor" stroke="none" />
        </g>
      );

    case 'pivot':
    case 'key':
    case 'auth':
    case 'lateral':
      // Cryptographic skeleton key with stepped algorithmic teeth
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="7.5" cy="12" r="4.5" />
          <circle cx="7.5" cy="12" r="1.5" fill="currentColor" stroke="none" />
          <path d="M12 12h9" />
          <path d="M16 12v3.5M19 12v2" strokeWidth={strokeWidth * 1.05} />
        </g>
      );

    case 'crown':
    case 'vault':
    case 'diamond':
    case 'objective':
      // Geometric faceted datastore crown jewel vault doodle
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M6 4h12l4 6-10 11L2 10l4-6z" fill="currentColor" fillOpacity="0.12" />
          <path d="M2 10h20" />
          <path d="M10 4l-2 6 4 11 4-11-2-6" />
        </g>
      );

    case 'target':
    case 'reticle':
      // Sniper sighting reticle with crosshairs
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="8" />
          <circle cx="12" cy="12" r="3.2" />
          <circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" />
          <line x1="12" y1="2" x2="12" y2="5" />
          <line x1="12" y1="19" x2="12" y2="22" />
          <line x1="2" y1="12" x2="5" y2="12" />
          <line x1="19" y1="12" x2="22" y2="12" />
        </g>
      );

    case 'shield':
    case 'defense':
    case 'mitigation':
      // Tactical defense shield doodle with security crest
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 2.5L4.5 5.5v6c0 5 3.5 9.5 7.5 10.5 4-1 7.5-5.5 7.5-10.5v-6L12 2.5z" fill="currentColor" fillOpacity="0.12" />
          <path d="M12 7.5v9M8.5 11l3.5 3.5 3.5-3.5" />
        </g>
      );

    case 'probe':
    case 'rocket':
    case 'missile':
      // Tactical sensor telemetry probe doodle
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 2.5c2.2 2.8 3.8 6.5 3.8 9.5l-3.8 3.8-3.8-3.8c0-3 1.6-6.7 3.8-9.5z" fill="currentColor" fillOpacity="0.12" />
          <path d="M8.2 12l-3.2 3.5 3.2 1M15.8 12l3.2 3.5-3.2 1" />
          <path d="M10.5 16l1.5 5 1.5-5" />
          <circle cx="12" cy="8" r="1.2" fill="currentColor" stroke="none" />
        </g>
      );

    case 'check':
    case 'verified':
    case 'success':
      // Technical drafting validation checkmark
      return (
        <g strokeWidth={strokeWidth * 1.15} strokeLinecap="round" strokeLinejoin="round">
          <path d="M4.5 12.5l5 5L19.5 6.5" />
        </g>
      );

    case 'warning':
    case 'alert':
      // Drafting hazard triangle with exclamation stem & dot
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 3.5L2.5 20h19L12 3.5z" fill="currentColor" fillOpacity="0.12" />
          <line x1="12" y1="9" x2="12" y2="13.5" />
          <circle cx="12" cy="17" r="1.1" fill="currentColor" stroke="none" />
        </g>
      );

    case 'lock':
      // Cryptographic padlock doodle
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <rect x="5.5" y="10" width="13" height="11" rx="2" />
          <path d="M8.5 10V7a3.5 3.5 0 0 1 7 0v3" />
          <circle cx="12" cy="14.5" r="1.3" fill="currentColor" stroke="none" />
          <line x1="12" y1="15.8" x2="12" y2="18" />
        </g>
      );

    case 'radar':
      // Radial scanning sweep doodle
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="8.5" />
          <circle cx="12" cy="12" r="4.5" />
          <line x1="12" y1="12" x2="18" y2="6" strokeWidth={strokeWidth * 1.1} />
          <circle cx="12" cy="12" r="1.2" fill="currentColor" stroke="none" />
        </g>
      );

    case 'audio':
    case 'speaker':
    case 'sound':
      // Technical speaker doodle with sonic waves
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M11 5L6 9H2.5v6H6l5 4V5z" fill="currentColor" fillOpacity="0.12" />
          <path d="M15.5 8.5a5 5 0 0 1 0 7" />
          <path d="M18.8 5.2a9.5 9.5 0 0 1 0 13.6" />
        </g>
      );

    case 'mute':
    case 'muted':
      // Technical muted speaker doodle with cancellation strike
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M11 5L6 9H2.5v6H6l5 4V5z" fill="currentColor" fillOpacity="0.12" />
          <line x1="22" y1="9" x2="16" y2="15" strokeWidth={strokeWidth * 1.1} />
          <line x1="16" y1="9" x2="22" y2="15" strokeWidth={strokeWidth * 1.1} />
        </g>
      );

    case 'fullscreen':
      // Technical expand viewport cross-brackets doodle
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M8 3H4.5a1.5 1.5 0 0 0-1.5 1.5V8m20 0V4.5a1.5 1.5 0 0 0-1.5-1.5H16m0 20h4.5a1.5 1.5 0 0 0 1.5-1.5V16M3 16v4.5A1.5 1.5 0 0 0 4.5 22H8" />
        </g>
      );

    case 'window':
    case 'minimize':
      // Technical contract viewport brackets doodle
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <path d="M8 3v3.5A1.5 1.5 0 0 1 6.5 8H3m18 0h-3.5A1.5 1.5 0 0 1 16 6.5V3m0 18v-3.5a1.5 1.5 0 0 1 1.5-1.5H21M3 16h3.5A1.5 1.5 0 0 1 8 17.5V21" />
        </g>
      );

    case 'gear':
    default:
      // Technical drafting cogwheel doodle
      return (
        <g strokeWidth={strokeWidth} strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="3.5" />
          <path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1l2.1-2.1M17 7l2.1-2.1" />
        </g>
      );
  }
};

/**
 * Standard HTML SVG Doodle Icon component
 */
export const DoodleIcon: React.FC<DoodleIconProps> = ({
  name,
  size = 15,
  className = '',
  style,
  ...props
}) => {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      className={`inline-block shrink-0 align-middle select-none transition-colors ${className}`}
      style={style}
      aria-hidden="true"
      {...props}
    >
      {renderDoodlePaths(name)}
    </svg>
  );
};

/**
 * Direct SVG <g> component for embedding into SVG canvases (e.g. GraphView)
 */
export const DoodleGroup: React.FC<DoodleGroupProps> = ({
  name,
  x = 0,
  y = 0,
  size = 14,
  color = 'currentColor',
  strokeWidth = 1.8,
  className = '',
}) => {
  const scale = size / 24;
  return (
    <g
      transform={`translate(${x}, ${y}) scale(${scale})`}
      stroke={color}
      fill="none"
      className={className}
      pointerEvents="none"
    >
      {renderDoodlePaths(name, strokeWidth)}
    </g>
  );
};

/**
 * Helper to resolve appropriate doodle icon name from node attributes or stage index
 */
export const resolveStageDoodle = (
  idxOrType: number | string,
  isFirst = false,
  isLast = false
): DoodleName => {
  if (typeof idxOrType === 'number') {
    switch (idxOrType) {
      case 0:
        return 'osint';
      case 1:
        return 'ingress';
      case 2:
        return 'service';
      case 3:
        return 'exploit';
      case 4:
        return 'pivot';
      case 5:
      case 6:
        return 'crown';
      default:
        return 'ingress';
    }
  }

  const str = String(idxOrType).toLowerCase();
  if (isFirst || str.includes('osint') || str.includes('recon') || str.includes('crt.sh') || str.includes('doh') || str.includes('rdap')) {
    return 'osint';
  }
  if (isLast || str.includes('crown') || str.includes('coredb') || str.includes('vault') || str.includes('payment') || str.includes('jewel')) {
    return 'crown';
  }
  if (str.includes('cve') || str.includes('cwe') || str.includes('vuln') || str.includes('exploit') || str.includes('alert')) {
    return 'exploit';
  }
  if (str.includes(':') || str.includes('port') || str.includes('service') || str.includes('listener')) {
    return 'service';
  }
  if (str.includes('auth') || str.includes('proxy') || str.includes('ssh') || str.includes('pivot') || str.includes('jump')) {
    return 'pivot';
  }
  return 'ingress';
};

export default DoodleIcon;
