"""Generate revised source-audited poster figures; no application code is changed."""
from __future__ import annotations
from html import escape
from pathlib import Path

OUT=Path(__file__).parent
RED,INK,GRAY,PALE,PINK,WHITE="#8F1D2C","#202124","#68727C","#E7EAED","#F7E8EA","#FFFFFF"
FONT="Arial, Helvetica, sans-serif"
FIGS={"01-introduction":(2820,2370,"Document feature versus dangerous behavior"),"02-methods":(6150,1380,"Implemented Security Engine workflow"),"03-pdf-correlation":(2820,1890,"PDF action-chain correlation"),"04-office-analysis":(2820,1110,"Office relationship analysis"),"05-latency":(2820,900,"Frozen scan latency comparison"),"06-results":(2760,2670,"Frozen results and hosted PDF regressions"),"07-conclusion":(2820,2190,"Research contributions and limitations")}

def S(w,h,title,body):
 return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img" aria-labelledby="title desc"><title id="title">{escape(title)}</title><desc id="desc">Source-audited FilesMagic Security Engine poster figure.</desc><rect width="100%" height="100%" fill="{WHITE}"/><style>text{{font-family:{FONT};fill:{INK}}}.t{{font-size:108px;font-weight:700}}.h{{font-size:68px;font-weight:700}}.b{{font-size:50px}}.s{{font-size:38px;fill:{GRAY}}}.xs{{font-size:32px;fill:{GRAY}}}.line{{stroke:{GRAY};stroke-width:9;fill:none}}.red{{stroke:{RED};stroke-width:13;fill:none}}.box{{fill:{PALE};stroke:{GRAY};stroke-width:5}}.pink{{fill:{PINK};stroke:{RED};stroke-width:6}}.white{{fill:{WHITE};stroke:{GRAY};stroke-width:5}}</style>{body}</svg>'''
def T(x,y,text,c="b",a="start"):
 gap={"t":116,"h":78,"b":60,"s":48,"xs":39}[c]
 return "".join(f'<text x="{x}" y="{y+i*gap}" class="{c}" text-anchor="{a}">{escape(line)}</text>' for i,line in enumerate(text.split("\n")))
def B(x,y,w,h,label,detail="",kind="white"):
 return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="22" class="{kind}"/>'+T(x+w/2,y+82,label,"h","middle")+(T(x+w/2,y+152,detail,"s","middle") if detail else "")
def A(x1,y1,x2,y2,red=False):
 color=RED if red else GRAY
 return f'<path d="M{x1} {y1} L{x2} {y2}" stroke="{color}" stroke-width="{10 if red else 7}" fill="none" marker-end="url(#{"r" if red else "n"})"/>'
def D():
 return f'<defs><marker id="n" markerWidth="16" markerHeight="16" refX="13" refY="8" orient="auto"><path d="M0 0L16 8L0 16Z" fill="{GRAY}"/></marker><marker id="r" markerWidth="16" markerHeight="16" refX="13" refY="8" orient="auto"><path d="M0 0L16 8L0 16Z" fill="{RED}"/></marker></defs>'

def intro():
 b=D()+T(140,145,"Document features need context","t")+T(140,215,"Static analysis asks whether an activation path is actually evidenced.","s")
 b+=B(150,340,1160,1450,"Ordinary document features","often legitimate","white")
 for y,label,detail in [(600,"Form or link","a reader may choose to interact"),(920,"Attachment","may simply be present"),(1240,"Macro or script","may not be reached automatically")]: b+=B(280,y,900,190,label,detail,"box")
 b+=B(1510,340,1160,1450,"Potentially dangerous activation","requires a proven path","pink")
 b+=B(1660,580,860,190,"Automatic trigger","on open / automatic entry","white")+A(2090,790,2090,905,True)+B(1660,925,860,190,"Active step","script / procedure / relationship","white")+A(2090,1135,2090,1250,True)+B(1660,1270,860,190,"Effect or delivery","launch / export / external load","white")
 return b+f'<rect x="150" y="1930" width="2520" height="230" rx="24" class="box"/>'+T(1410,2025,"Presence alone is context. A verified path justifies a stronger finding.","h","middle")+T(1410,2080,"SAFE means no known indicator found by completed analysis - not proof of harmlessness.","s","middle")
def methods():
 b=D()+T(120,115,"Implemented Security Engine workflow","t")+T(120,168,"Standalone research service: it does not invoke the FilesMagic conversion service.","s")
 for x,w,label,detail,kind in [(120,1100,"1  Upload","token, size, and hash checks","white"),(1510,1100,"2  Isolation","fresh worker and strict Linux controls","pink"),(2900,1460,"3  Analysis","reference, unified, and coverage checks","white"),(4650,1200,"4  Verdict","findings plus completeness","pink")]: b+=B(x,250,w,840,label,detail,kind)
 b+=A(1220,670,1480,670)+A(2610,670,2870,670,True)+A(4390,670,4620,670)+T(670,810,"file bytes accepted\nafter authorization","b","middle")+T(2060,810,"namespace, routes,\ncapabilities, limits","b","middle")
 b+=B(3060,500,1140,165,"Reference scanners","signatures, PDF, Office, structural","box")+B(3060,705,1140,165,"Unified research components","chains, activation, fields, correlation","pink")+B(3060,910,1140,165,"Coverage checks","required regions; fail closed","box")+T(5250,770,"SAFE\nSUSPICIOUS\nMALICIOUS\nUNABLE TO SCAN","h","middle")
 return b+f'<rect x="120" y="1130" width="5730" height="150" rx="20" class="box"/>'+T(2985,1195,"Reference scanners remain the baseline; the research engine adds structured evidence and coverage handling.","b","middle")
def pdf():
 b=D()+T(130,125,"Same ingredients. Different relationship.","t")+T(130,210,"Frozen cases 5a and 5b: severity changes only when the script is proven to reach the attachment.","s")
 for x,case,outcome,linked in [(150,"5a - attachment is unrelated","SUSPICIOUS",False),(1480,"5b - script exports attachment","MALICIOUS",True)]:
  b+=B(x,310,1190,1220,case,"","pink" if linked else "white")+B(x+115,520,400,180,"Open action","automatic trigger","box")+A(x+315,710,x+315,875,True)+B(x+115,900,400,180,"JavaScript","active step","box")+B(x+675,900,400,180,"Attachment f","embedded file","box")
  b+= A(x+530,990,x+650,990,True)+T(x+595,870,"exports f","b","middle") if linked else f'<path d="M{x+530} 990 H{x+650}" stroke="{GRAY}" stroke-width="9" stroke-dasharray="24 20"/><text x="{x+590}" y="870" class="b" text-anchor="middle">no path</text>'
  b+=f'<rect x="{x+110}" y="1210" width="970" height="180" rx="18" fill="{PINK if linked else PALE}"/>'+T(x+595,1290,outcome,"t","middle")+T(x+595,1340,"unified engine outcome","s","middle")
 return b+T(1410,1690,"Unified result: 5a SUSPICIOUS; 5b MALICIOUS.","h","middle")+T(1410,1750,"Controlled synthetic fixtures - not a malware-detection accuracy measurement.","s","middle")
def office():
 b=D()+T(130,115,"Office relationships: declared is not active","t")+T(130,205,"Frozen cases 6b and 6c are alternative paths from the same declared external relationship.","s")+B(940,300,940,190,"External template relationship","declared in the package","box")
 b+=f'<path d="M1410 470 V560 H610 V640" class="line" marker-end="url(#n)"/><path d="M1410 470 V560 H2210 V640" class="red" marker-end="url(#r)"/>'+B(150,660,920,320,"6b - unreferenced","No Office-loaded part uses it\nRecorded as inactive context","white")+B(1750,660,920,320,"6c - loaded on open","Settings part references it\nRecorded as active on open","pink")
 return b+T(610,1040,"INFO: declared, not activated","b","middle")+T(2210,1040,"MEDIUM: external target used on open","b","middle")
def latency():
 b=T(130,110,"Frozen scan latency comparison","t")+T(130,162,"16 inert fixtures x 20 trials x engine = 320 scans per engine. Worker startup and IPC dominate wall time.","s")+f'<line x1="520" y1="730" x2="2660" y2="730" class="line"/>'
 for v in (0,200,400,600): x=520+v*3.35;b+=f'<line x1="{x}" y1="260" x2="{x}" y2="750" stroke="{PALE}" stroke-width="4"/>'+T(x,800,str(v),"xs","middle")
 for label,p50,p95,y,color in [("Reference",555.51,629.422,350,GRAY),("Unified",567.58,629.136,555,RED)]:
  w=p50*3.35;b+=T(480,y+62,label,"h","end")+f'<rect x="520" y="{y}" width="{w}" height="105" rx="16" fill="{color}"/>'+f'<text x="{520+w-35}" y="{y+68}" class="b" text-anchor="end" style="fill:{WHITE}">p50 {p50:.1f} ms</text>'+f'<line x1="{520+p95*3.35}" y1="{y-24}" x2="{520+p95*3.35}" y2="{y+130}" class="red"/>'+T(520+p95*3.35,y-40,f"p95 {p95:.1f}","xs","middle")
 return b
def results():
 b=T(130,125,"Results: frozen evidence + hosted rescans","t")+T(130,215,"The Nov. 9 evaluation and Nov. 14 regressions are different experiments and are not combined.","s")+B(150,350,2460,1070,"Frozen standalone evaluation - Nov. 9","offline Ubuntu VM; strict isolation; evaluated code eda2a08","pink")
 b+=T(780,700,"114 / 114","t","middle")+T(780,765,"expected scan outcomes","h","middle")+T(1840,700,"11 / 11","t","middle")+T(1840,765,"contribution checks","h","middle")+f'<line x1="1380" y1="570" x2="1380" y2="870" class="line"/>'+T(1380,1010,"Controlled checks, not a malware-detection accuracy percentage.","b","middle")+T(1380,1110,"Every frozen result reported no missing required isolation control.","b","middle")
 b+=B(150,1580,2460,800,"Hosted research Lab rescans - Nov. 14","one SHA-256-matched rescan of each pinned qpdf fixture; unified engine; strict isolation reported","white")+B(280,1880,980,250,"V4-aes.pdf","SAFE\n6 complete, 4 not applicable, 0 failed","box")+B(1500,1880,980,250,"bad-data.pdf","UNABLE TO SCAN\nLZW content decoding failed","pink")
 return b+T(1380,2260,"Evidence scope: two selected benign/parser-stress regressions; no repeated hosted trials or accuracy claim.","s","middle")
def conclusion():
 b=T(130,130,"What this research shows - and does not","t")+T(130,220,"Standalone static-analysis research prototype, not a production conversion gate.","s")+B(150,360,1210,1300,"Demonstrated","three source-backed contributions","pink")+B(1460,360,1210,1300,"Still limited","three essential boundaries","white")
 for i,s in enumerate(["Contextual PDF chains separate\nunrelated from delivered attachments.","Office/VBA analysis records\nactivation and call-path evidence.","Coverage gaps can fail closed\nin the unified research engine."]): b+=f'<circle cx="245" cy="{650+i*340}" r="25" fill="{RED}"/>'+T(305,660+i*340,s,"b")
 for i,s in enumerate(["No production FilesMagic\nconverter integration.","No real-world malware-detection\naccuracy claim.","No document execution; worker\ncontainment is not a full sandbox."]): b+=f'<circle cx="1555" cy="{650+i*340}" r="25" fill="{GRAY}"/>'+T(1615,660+i*340,s,"b")
 return b+f'<rect x="150" y="1820" width="2520" height="200" rx="22" class="box"/>'+T(1410,1910,"Future production gate: SAFE + complete + required coverage + required isolation.","h","middle")+T(1410,1970,"That integration is proposed, not implemented.","s","middle")

BUILDERS=[intro,methods,pdf,office,latency,results,conclusion]
CAPTIONS=["Ordinary document features are not inherently malicious; the engine distinguishes presence from an evidenced activation path.","Authorized upload, isolated worker, layered analysis, and a deterministic verdict; the converter is not invoked.","Frozen cases 5a and 5b differ only in whether the automatic script is evidenced to export the attachment.","A declared OOXML relationship is classified differently when unreferenced versus used by a part loaded on open.","Frozen 16-fixture comparison; worker startup and IPC dominate wall time and this is not a general benchmark.","Frozen outcomes are separate from two hosted Nov. 14 qpdf regressions, not a detection-accuracy study.","Bounded static analysis is demonstrated; integration, broad accuracy, and full sandboxing remain unvalidated."]
README="""# Source-audited poster figures - revised 2026-11-14

This folder contains seven large-type SVG/PNG poster figures, a contact sheet, captions, and this reproducible generator. Frozen figures use the Nov. 9 `eda2a08` record and `custom-engine-1668326` artifacts. The results figure separately uses `d4bb56f:docs/evidence/pdf-coverage-remediation-2026-11-13/staging-840a300c-2026-11-14.json`: two hosted SHA-256-matched qpdf rescans, not a replacement frozen run or an accuracy study.
"""
AUDIT="""# Architecture audit for poster claims

- `app/main.py:scan_file` authorizes the request, verifies hash/size before scan, invokes `worker.run`, calls `decision.decide`, and returns the result.
- `app/worker.py:run` launches a fresh bounded worker and kills its process group. `main` chooses reference/unified scanner sets; correlation runs only for unified scans.
- Linux controls are implemented in `network_isolation`, `verify_network_isolation`, `drop_capabilities`, `apply_limits`, `_audit_hook`, and `missing_controls`; strict mode refuses analysis when required controls are absent. Frozen sources: `tests/test_worker_linux.py` and `docs/evidence/final-eda2a08-run3/`.
- Reference scanners are YARA-X, PDF, Office, and custom structural analysis. The current unified research engine adds refined signatures, PDF chains, PDF integrity/coverage, VBA, OOXML, Word fields, and correlation.
- Verdict policy: HIGH/CRITICAL -> MALICIOUS; LOW/MEDIUM -> SUSPICIOUS; otherwise scanner failure/no applicable scanner -> UNABLE_TO_SCAN; else SAFE. The production converter gate remains proposed.
- Frozen Nov. 9: 114/114 outcomes and 11/11 checks, not general malware-detection accuracy. Hosted Nov. 14: two selected qpdf rescans at `840a300c`; verdicts/scanner counts/findings/worker-reported isolation were recorded, but raw hosted coverage fields were not exported.
"""
MAP="""# Source-to-figure evidence map

| Figure | Main evidence |
|---|---|
| 01 | `docs/engine-readiness-report.md`; `app/decision/__init__.py` |
| 02 | `app/main.py`; `app/worker.py`; `app/scanners/__init__.py`; `app/engine/__init__.py` |
| 03 | `docs/poster/figures/comparison.md`; `docs/evidence/custom-engine-1668326/`; `app/engine/pdf_chains.py` |
| 04 | `docs/poster/figures/comparison.md`; `app/engine/ooxml_links.py` |
| 05 | `docs/evidence/custom-engine-1668326/{reference,unified}/results.json` |
| 06 | `docs/evidence/final-eda2a08-run3/`; `d4bb56f:docs/evidence/pdf-coverage-remediation-2026-11-13/staging-840a300c-2026-11-14.json` |
| 07 | `docs/engine-readiness-report.md`; `app/worker.py`; post-freeze hosted remediation record |
"""
def main():
 OUT.mkdir(parents=True,exist_ok=True)
 for (n,(w,h,title)),build in zip(FIGS.items(),BUILDERS): (OUT/f"{n}.svg").write_text(S(w,h,title,build()),encoding="utf-8")
 (OUT/"figure-captions.md").write_text("# Figure captions\n\n"+"\n\n".join(f"{i}. **{n}.** {c}" for i,((n,_),c) in enumerate(zip(FIGS.items(),CAPTIONS),1)),encoding="utf-8")
 (OUT/"README.md").write_text(README,encoding="utf-8");(OUT/"architecture-audit.md").write_text(AUDIT,encoding="utf-8");(OUT/"source-to-figure-evidence-map.md").write_text(MAP,encoding="utf-8")
 tiles=[]
 for i,(n,(w,h,_)) in enumerate(FIGS.items()):
  col,row=i%2,i//2;x,y=90+col*1450,130+row*860;z=min(1300/w,680/h);tiles += [f'<text x="{x}" y="{y-25}" font-family="{FONT}" font-size="32" font-weight="700" fill="{INK}">{i+1:02d}  {n[3:].replace("-"," ")}</text>',f'<rect x="{x}" y="{y}" width="1300" height="680" fill="white" stroke="{GRAY}" stroke-width="3"/>',f'<image href="{n}.svg" x="{x}" y="{y}" width="{w*z}" height="{h*z}" preserveAspectRatio="xMidYMid meet"/>']
 (OUT/"contact-sheet.svg").write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="3000" height="3550" viewBox="0 0 3000 3550"><rect width="100%" height="100%" fill="white"/><text x="90" y="70" font-family="{FONT}" font-size="46" font-weight="700" fill="{INK}">FilesMagic source-audited poster figures - revised 2026-11-14</text>'+''.join(tiles)+f'<text x="90" y="3500" font-family="{FONT}" font-size="28" fill="{GRAY}">Frozen Nov. 9 evidence and separately labeled hosted Nov. 14 PDF regressions.</text></svg>',encoding="utf-8")
if __name__=="__main__": main()
