#!/usr/bin/env python3
"""Capability probe + isolated lab preparation.

This command deliberately does not pretend to install arbitrary tools. The AI can use the
runtime's native package/MCP capabilities for installation, then re-run the probe to verify them.
"""
from __future__ import annotations
import shutil, subprocess, sys
from pathlib import Path

CAPS={
 'adb':(['adb'],['--version'],'Android SDK platform-tools'),'emulator':(['emulator'],['-version'],'Android Emulator'),
 'docker':(['docker'],['--version'],'Docker'),'node':(['node'],['--version'],'Node.js'),'python3':(['python3'],['--version'],'Python 3'),
 'nuclei':(['nuclei'],['-version'],'ProjectDiscovery nuclei'),'ffuf':(['ffuf'],['-V'],'ffuf'),'mitmproxy':(['mitmproxy','mitmdump'],['--version'],'mitmproxy'),
 'jadx':(['jadx'],['--version'],'jadx'),'frida':(['frida'],['--version'],'Frida tools'),'ios-simulator':(['xcrun','simctl'],['list'],'Xcode simulator (macOS only)')
}

def verify(exe,args):
 try:
  r=subprocess.run([exe,*args],capture_output=True,text=True,timeout=10)
  text=(r.stdout+r.stderr).strip().splitlines()
  return r.returncode==0,(text[0][:160] if text else f'exit {r.returncode}')
 except Exception as e: return False,str(e)[:160]

def main():
 args=sys.argv[1:]; root=Path(args[0]).resolve() if args and not args[0].startswith('-') else Path.cwd()
 check_only='--check-only' in args; selected=args[args.index('--capability')+1] if '--capability' in args and args.index('--capability')+1<len(args) else None
 if selected and selected not in CAPS: print('unknown capability'); return 2
 names=[selected] if selected else list(CAPS)
 rows=[]; states=[]
 (root/'lab').mkdir(parents=True,exist_ok=True)
 for name in names:
  bins,vargs,purpose=CAPS[name]
  exe=next((b for b in bins if shutil.which(b)),None)
  if not exe:
   state='MISSING'
   if not check_only: (root/'lab'/name).mkdir(parents=True,exist_ok=True)
   rows.append((name,state,purpose,''))
  else:
   ok,detail=verify(exe,vargs); state='READY' if ok else 'FAILED'; rows.append((name,state,purpose,detail))
  states.append(state)
 rt=root/'11_runtime'; rt.mkdir(parents=True,exist_ok=True)
 lines=['# Tool registry','tools:']
 for name,state,purpose,detail in rows:
  lines += [f'  - name: {name}',f'    state: "{state}"',f'    purpose: "{purpose}"',f'    detail: "{detail}"']
 (rt/'tool-registry.yaml').write_text('\n'.join(lines)+'\n')
 overall='READY' if all(s=='READY' for s in states) else ('FAILED' if 'FAILED' in states else 'MISSING')
 (rt/'lab-status.yaml').write_text(f'status: {overall}\nprovisioner: tools/provision.py\nisolated_lab: lab/\ninstallation_policy: ai-runtime-managed\nauto_exploit: false\n')
 print(f'capability probe: {overall} ({len(rows)} capabilities)'); return 0
if __name__=='__main__': raise SystemExit(main())
