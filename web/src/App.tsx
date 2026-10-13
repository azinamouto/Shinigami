import { useState } from 'react'
import {
  Activity, ArrowDownToLine, ArrowRight, Check, ChevronDown, CircleHelp,
  Clock3, FileJson, FileSearch, Fingerprint, FolderOpen, Github, LayoutDashboard,
  Menu, Radar, ScanLine, Settings2, Shield, ShieldAlert, TerminalSquare, X,
} from 'lucide-react'

type Page = 'Overview' | 'Scan workspace' | 'Findings' | 'Reports' | 'Settings'
const pages: { name: Page; icon: typeof Shield }[] = [
  { name: 'Overview', icon: LayoutDashboard },
  { name: 'Scan workspace', icon: ScanLine },
  { name: 'Findings', icon: ShieldAlert },
  { name: 'Reports', icon: FileSearch },
  { name: 'Settings', icon: Settings2 },
]
const scanners = [
  { name: 'Native', description: 'Configuration and source checks', icon: Radar },
  { name: 'Gitleaks', description: 'Exposed credentials and secrets', icon: Fingerprint },
  { name: 'OSV', description: 'Known dependency vulnerabilities', icon: ShieldAlert },
]

function App() {
  const [page, setPage] = useState<Page>('Overview')
  const [mobileNav, setMobileNav] = useState(false)
  const [scanner, setScanner] = useState('All scanners')
  const [path, setPath] = useState('')
  const navigate = (next: Page) => { setPage(next); setMobileNav(false) }
  return (
    <div className="shell">
      <aside className={`sidebar ${mobileNav ? 'sidebar-open' : ''}`}>
        <div className="brand"><div className="brand-mark"><Shield size={21} strokeWidth={2.2} /></div><div><strong>SHINIGAMI<span className="brand-dot">.</span></strong><small>SECURITY WORKSPACE</small></div><button className="mobile-close" onClick={() => setMobileNav(false)} aria-label="Close navigation"><X size={19}/></button></div>
        <div className="sidebar-caption">WORKSPACE</div>
        <nav aria-label="Primary navigation">{pages.map(({name, icon: Icon}) => <button key={name} className={`nav-item ${page === name ? 'active' : ''}`} onClick={() => navigate(name)}><Icon size={17} strokeWidth={1.8}/><span>{name}</span>{page === name && <span className="nav-indicator"/>}</button>)}</nav>
        <div className="sidebar-bottom"><div className="local-card"><div className="local-title"><span className="status-dot"/> Local mode</div><p>Scans stay on your machine when the Go API is connected.</p></div><a href="https://github.com/azinamouto/Shinigami" target="_blank" rel="noreferrer" className="github-link"><Github size={17}/> GitHub repository <ArrowRight size={15}/></a><div className="sidebar-version">SHINIGAMI / UI PREVIEW 01</div></div>
      </aside>
      {mobileNav && <button className="scrim" onClick={() => setMobileNav(false)} aria-label="Close navigation"/>}
      <main className="main">
        <header className="topbar"><button className="mobile-menu" onClick={() => setMobileNav(true)} aria-label="Open navigation"><Menu size={21}/></button><div className="breadcrumbs">WORKSPACE <span>/</span> <strong>{page.toUpperCase()}</strong></div><div className="topbar-right"><span className="preview-pill"><span className="status-dot"/> UI PREVIEW</span><span className="avatar">S</span></div></header>
        <div className="content">
          {page === 'Overview' && <>
            <div className="eyebrow"><span className="eyebrow-line"/> COMMAND CENTER</div>
            <div className="hero"><div><h1>Security, without<br/><em>the noise.</em></h1><p>A focused workspace to inspect your code, understand risks, and take action. Built for the Shinigami engine.</p><button className="primary-btn" onClick={() => navigate('Scan workspace')}><ScanLine size={17}/> Open scan workspace <ArrowRight size={16}/></button></div><div className="hero-symbol" aria-hidden="true"><Shield size={164} strokeWidth={0.65}/><div className="hero-crosshair">+</div></div></div>
            <div className="section-header"><div><div className="eyebrow muted">AT A GLANCE</div><h2>Security overview</h2></div><span className="muted-note"><Clock3 size={14}/> Awaiting first connected scan</span></div>
            <div className="stats"><div className="stat"><span>Total findings</span><strong>—</strong><small>Connect the API for live data</small></div><div className="stat"><span>Critical issues</span><strong>—</strong><small>No scan data yet</small></div><div className="stat"><span>High severity</span><strong>—</strong><small>No scan data yet</small></div><div className="stat"><span>Scanners supported</span><strong>03</strong><small>Native / Gitleaks / OSV</small></div></div>
            <div className="section-header lower"><div><div className="eyebrow muted">YOUR TOOLKIT</div><h2>Scanning engines</h2></div><button className="text-action" onClick={() => navigate('Scan workspace')}>Go to workspace <ArrowRight size={15}/></button></div>
            <div className="scanner-list">{scanners.map(({name,description,icon:Icon},index)=><div className="scanner-row" key={name}><div className="scanner-icon"><Icon size={20}/></div><div className="scanner-details"><strong>{name}</strong><span>{description}</span></div><span className="scanner-index">0{index+1}</span><ArrowRight size={16} className="row-arrow"/></div>)}</div>
          </>}
          {page === 'Scan workspace' && <><PageHeading kicker="SCAN CONTROL" title="Scan workspace" description="Configure a repository scan. Execution becomes available when the local Go API is connected."/><section className="panel"><div className="panel-head"><div><h2>New scan</h2><p>Choose a local repository and scanning engine.</p></div><ScanLine size={22}/></div><label className="field-label" htmlFor="repo-path">REPOSITORY PATH</label><div className="input-wrap"><FolderOpen size={18}/><input id="repo-path" placeholder="C:\\path\\to\\repository" value={path} onChange={e=>setPath(e.target.value)}/></div><label className="field-label" htmlFor="scanner-select">SCANNING ENGINE</label><div className="select-wrap"><select id="scanner-select" value={scanner} onChange={e=>setScanner(e.target.value)}><option>All scanners</option><option>Native</option><option>Gitleaks</option><option>OSV</option></select><ChevronDown size={17}/></div><div className="panel-foot"><span><CircleHelp size={15}/> Scanning is disabled in this frontend-only preview.</span><button className="primary-btn disabled" disabled><ScanLine size={17}/> Run security scan</button></div></section><div className="info-strip"><TerminalSquare size={20}/><div><strong>CLI still works</strong><p>Run <code>go run ./cmd/shinigami scan -scanner all .</code> from the project root until API integration is complete.</p></div></div></>}
          {page === 'Findings' && <><PageHeading kicker="SECURITY RESULTS" title="Findings" description="Review detected issues, their locations, and suggested remediation."/><EmptyState icon={ShieldAlert} title="No scan results available" text="Once the local API is connected and a scan completes, findings will appear here." action={() => navigate('Scan workspace')}/></>}
          {page === 'Reports' && <><PageHeading kicker="EXPORT CENTER" title="Reports" description="Export completed scans in machine-readable formats."/><div className="report-grid"><div className="report-card"><FileJson size={25}/><h2>JSON</h2><p>Structured findings for scripts and integrations.</p><button disabled><ArrowDownToLine size={16}/> Available after API integration</button></div><div className="report-card"><FileSearch size={25}/><h2>SARIF 2.1.0</h2><p>Standardized output compatible with security analysis workflows.</p><button disabled><ArrowDownToLine size={16}/> Available after API integration</button></div></div></>}
          {page === 'Settings' && <><PageHeading kicker="PREFERENCES" title="Settings" description="Your local Shinigami workspace configuration."/><section className="panel settings-panel"><h2>Runtime status</h2><div className="setting-row"><div><strong>Frontend</strong><span>React + TypeScript / Vite</span></div><span className="status-label"><Check size={15}/> Ready</span></div><div className="setting-row"><div><strong>Go scanner API</strong><span>Local API integration planned for Patch 02</span></div><span className="pending-label">Not connected</span></div><div className="setting-row"><div><strong>Theme</strong><span>Obsidian / Crimson / White</span></div><span className="pending-label">Dark</span></div></section></>}
          <footer><span>SHINIGAMI <span className="red">/</span> SECURITY WORKSPACE</span><span>LOCAL-FIRST BY DESIGN <Activity size={13}/></span></footer>
        </div>
      </main>
    </div>
  )
}
function PageHeading({kicker,title,description}:{kicker:string;title:string;description:string}){return <div className="page-heading"><div className="eyebrow"><span className="eyebrow-line"/>{kicker}</div><h1>{title}<span className="red">.</span></h1><p>{description}</p></div>}
function EmptyState({icon:Icon,title,text,action}:{icon:typeof Shield;title:string;text:string;action:()=>void}){return <div className="empty-state"><div className="empty-icon"><Icon size={30} strokeWidth={1.5}/></div><h2>{title}</h2><p>{text}</p><button className="secondary-btn" onClick={action}>Open scan workspace <ArrowRight size={16}/></button></div>}
export default App
