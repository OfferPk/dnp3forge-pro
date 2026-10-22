/\* \==============================================================================  
   DNP3Forge Pro \- Modern Substation SCADA / NOC Dark Glassmorphism CSS  
   \============================================================================== \*/

:root {  
  \--bg-primary: \#080c14;  
  \--bg-secondary: \#0f172a;  
  \--bg-card: rgba(15, 23, 42, 0.75);  
  \--bg-card-hover: rgba(30, 41, 59, 0.85);  
  \--border-color: rgba(51, 65, 85, 0.5);  
  \--border-glow: rgba(245, 158, 11, 0.4);  
    
  \--text-main: \#f8fafc;  
  \--text-muted: \#94a3b8;  
  \--text-dim: \#64748b;  
    
  \--accent-amber: \#f59e0b;  
  \--accent-cyan: \#06b6d4;  
  \--accent-green: \#10b981;  
  \--accent-red: \#ef4444;  
  \--accent-blue: \#3b82f6;  
  \--accent-purple: \#8b5cf6;  
    
  \--font-sans: 'Inter', \-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;  
  \--font-mono: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;  
    
  \--radius-sm: 6px;  
  \--radius-md: 10px;  
  \--radius-lg: 16px;  
    
  \--shadow-main: 0 10px 25px \-5px rgba(0, 0, 0, 0.6), 0 8px 10px \-6px rgba(0, 0, 0, 0.6);  
}

\* {  
  box-sizing: border-box;  
  margin: 0;  
  padding: 0;  
}

body {  
  background-color: var(--bg-primary);  
  color: var(--text-main);  
  font-family: var(--font-sans);  
  line-height: 1.5;  
  min-height: 100vh;  
  display: flex;  
  flex-direction: column;  
}

header {  
  background: rgba(15, 23, 42, 0.9);  
  backdrop-filter: blur(12px);  
  border-bottom: 1px solid var(--border-color);  
  padding: 1rem 2rem;  
  position: sticky;  
  top: 0;  
  z-index: 100;  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
}

.logo-area {  
  display: flex;  
  align-items: center;  
  gap: 0.85rem;  
}

.logo-badge {  
  background: linear-gradient(135deg, var(--accent-amber), \#d97706);  
  color: \#000;  
  font-weight: 900;  
  font-size: 1.1rem;  
  padding: 0.35rem 0.75rem;  
  border-radius: var(--radius-sm);  
  letter-spacing: 0.5px;  
  box-shadow: 0 0 12px rgba(245, 158, 11, 0.4);  
}

.logo-title h1 {  
  font-size: 1.35rem;  
  font-weight: 700;  
  letter-spacing: \-0.5px;  
  color: \#fff;  
}

.logo-title p {  
  font-size: 0.75rem;  
  color: var(--text-muted);  
}

.badge {  
  display: inline-flex;  
  align-items: center;  
  gap: 0.4rem;  
  font-size: 0.75rem;  
  font-weight: 600;  
  padding: 0.25rem 0.65rem;  
  border-radius: 9999px;  
  text-transform: uppercase;  
  letter-spacing: 0.5px;  
}

.badge-live {  
  background: rgba(245, 158, 11, 0.15);  
  color: var(--accent-amber);  
  border: 1px solid rgba(245, 158, 11, 0.3);  
}

.pulse-dot {  
  width: 7px;  
  height: 7px;  
  background-color: var(--accent-amber);  
  border-radius: 50%;  
  box-shadow: 0 0 8px var(--accent-amber);  
  animation: pulse 2s infinite;  
}

@keyframes pulse {  
  0% { transform: scale(0.95); opacity: 0.8; }  
  50% { transform: scale(1.3); opacity: 1; }  
  100% { transform: scale(0.95); opacity: 0.8; }  
}

main {  
  flex: 1;  
  max-width: 1600px;  
  width: 100%;  
  margin: 0 auto;  
  padding: 1.5rem 2rem;  
  display: flex;  
  flex-direction: column;  
  gap: 1.5rem;  
}

.tab-bar {  
  display: flex;  
  gap: 0.5rem;  
  border-bottom: 1px solid var(--border-color);  
  padding-bottom: 0.5rem;  
  overflow-x: auto;  
}

.tab-btn {  
  background: transparent;  
  border: none;  
  color: var(--text-muted);  
  font-size: 0.95rem;  
  font-weight: 600;  
  padding: 0.6rem 1.2rem;  
  border-radius: var(--radius-sm);  
  cursor: pointer;  
  transition: all 0.2s ease;  
  display: flex;  
  align-items: center;  
  gap: 0.5rem;  
  white-space: nowrap;  
}

.tab-btn:hover {  
  color: var(--text-main);  
  background: rgba(255, 255, 255, 0.05);  
}

.tab-btn.active {  
  color: var(--accent-amber);  
  background: rgba(245, 158, 11, 0.12);  
  border: 1px solid rgba(245, 158, 11, 0.3);  
}

.tab-content {  
  display: none;  
}

.tab-content.active {  
  display: block;  
}

.grid-2 {  
  display: grid;  
  grid-template-columns: 1fr 1fr;  
  gap: 1.5rem;  
}

@media (max-width: 1100px) {  
  .grid-2 {  
    grid-template-columns: 1fr;  
  }  
}

.card {  
  background: var(--bg-card);  
  backdrop-filter: blur(8px);  
  border: 1px solid var(--border-color);  
  border-radius: var(--radius-md);  
  padding: 1.5rem;  
  box-shadow: var(--shadow-main);  
  transition: border-color 0.2s;  
}

.card:hover {  
  border-color: var(--border-glow);  
}

.card-header {  
  display: flex;  
  justify-content: space-between;  
  align-items: center;  
  margin-bottom: 1.25rem;  
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);  
  padding-bottom: 0.75rem;  
}

.card-header h2, .card-header h3 {  
  font-size: 1.15rem;  
  font-weight: 700;  
  color: var(--text-main);  
}

.form-group {  
  margin-bottom: 1rem;  
}

.form-group label {  
  display: block;  
  font-size: 0.82rem;  
  font-weight: 600;  
  color: var(--text-muted);  
  margin-bottom: 0.4rem;  
}

.form-control {  
  width: 100%;  
  background: var(--bg-secondary);  
  border: 1px solid var(--border-color);  
  border-radius: var(--radius-sm);  
  color: var(--text-main);  
  padding: 0.6rem 0.85rem;  
  font-size: 0.9rem;  
  font-family: inherit;  
  transition: all 0.2s ease;  
}

.form-control:focus {  
  outline: none;  
  border-color: var(--accent-amber);  
  box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);  
}

select.form-control {  
  cursor: pointer;  
}

.btn {  
  display: inline-flex;  
  align-items: center;  
  justify-content: center;  
  gap: 0.5rem;  
  padding: 0.65rem 1.25rem;  
  font-size: 0.88rem;  
  font-weight: 600;  
  border-radius: var(--radius-sm);  
  border: none;  
  cursor: pointer;  
  transition: all 0.2s;  
  text-decoration: none;  
}

.btn-primary {  
  background: linear-gradient(135deg, var(--accent-amber), \#d97706);  
  color: \#000;  
  font-weight: 700;  
  box-shadow: 0 4px 12px rgba(245, 158, 11, 0.3);  
}

.btn-primary:hover {  
  filter: brightness(1.1);  
  box-shadow: 0 4px 16px rgba(245, 158, 11, 0.4);  
}

.hex-view {  
  background: \#030712;  
  border: 1px solid rgba(255, 255, 255, 0.08);  
  border-radius: var(--radius-sm);  
  padding: 1rem;  
  font-family: var(--font-mono);  
  font-size: 0.82rem;  
  line-height: 1.6;  
  color: \#fde68a;  
  overflow-x: auto;  
  white-space: pre-wrap;  
  word-break: break-all;  
  max-height: 280px;  
}

pre.code-block {  
  background: \#030712;  
  border: 1px solid rgba(255, 255, 255, 0.08);  
  border-radius: var(--radius-sm);  
  padding: 1rem;  
  font-family: var(--font-mono);  
  font-size: 0.82rem;  
  line-height: 1.5;  
  color: \#e2e8f0;  
  overflow-x: auto;  
  max-height: 420px;  
}

.score-badge-large {  
  font-size: 2.5rem;  
  font-weight: 800;  
  text-align: center;  
  padding: 1rem;  
  border-radius: var(--radius-md);  
  margin-bottom: 1rem;  
}

.grade-A {  
  background: rgba(16, 185, 129, 0.15);  
  color: var(--accent-green);  
  border: 1px solid rgba(16, 185, 129, 0.4);  
}

.grade-F {  
  background: rgba(239, 68, 68, 0.15);  
  color: var(--accent-red);  
  border: 1px solid rgba(239, 68, 68, 0.4);  
}

.audit-item {  
  display: flex;  
  justify-content: space-between;  
  align-items: flex-start;  
  padding: 0.85rem;  
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);  
  font-size: 0.88rem;  
}

.audit-item:last-child {  
  border-bottom: none;  
}

.audit-meta {  
  flex: 1;  
}

.audit-title {  
  font-weight: 600;  
  color: \#fff;  
  margin-bottom: 0.2rem;  
}

.audit-desc {  
  font-size: 0.78rem;  
  color: var(--text-muted);  
}

.audit-score {  
  font-family: var(--font-mono);  
  font-weight: 700;  
  margin-left: 1rem;  
}

.score-pass { color: var(--accent-green); }  
.score-warn { color: var(--accent-amber); }  
.score-fail { color: var(--accent-red); }

footer {  
  border-top: 1px solid var(--border-color);  
  padding: 1.5rem 2rem;  
  text-align: center;  
  font-size: 0.8rem;  
  color: var(--text-dim);  
  background: var(--bg-secondary);  
}  
