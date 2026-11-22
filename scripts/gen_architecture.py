#!/usr/bin/env python3
"""Generate the diagram, component tables and flows in docs/ARCHITECTURE.md from docs/architecture.json.

    python3 scripts/gen_architecture.py            # rewrite the generated section in place
    python3 scripts/gen_architecture.py --check    # exit 1 if the file is stale or the map is inconsistent

The JSON is the single source of truth. Before generating, the map is validated against the repository:
every named source file must exist, every edge/flow must reference real nodes, and every flow step must be
connected by a declared edge. The hand-written sections of ARCHITECTURE.md (outside the markers) are untouched.
"""
import json, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAP = os.path.join(ROOT, "docs", "architecture.json")
DOC = os.path.join(ROOT, "docs", "ARCHITECTURE.md")
BEGIN, END = "<!-- BEGIN GENERATED: docs/architecture.json (edit the JSON, then run scripts/gen_architecture.py) -->", "<!-- END GENERATED -->"
SOURCE_DIRS = ("src", os.path.join("include", "recon"))


def fail(msg):
    print(f"gen_architecture: {msg}", file=sys.stderr)
    sys.exit(1)


def load_and_validate():
    with open(MAP, encoding="utf-8") as f:
        m = json.load(f)
    lanes = {}
    for l in m["lanes"]:
        if l["id"] in lanes:
            fail(f"duplicate lane id {l['id']!r}")
        lanes[l["id"]] = l
    nodes = {}
    for n in m["nodes"]:
        if n["id"] in nodes:
            fail(f"duplicate node id {n['id']!r}")
        if n["lane"] not in lanes:
            fail(f"node {n['id']!r} is in unknown lane {n['lane']!r}")
        if n["id"] in lanes or any(n["id"] == "lane_" + k for k in lanes):
            fail(f"node id {n['id']!r} collides with a lane id")
        for fname in [x.strip() for x in n.get("file", "").split(",") if x.strip()]:
            if not any(os.path.exists(os.path.join(ROOT, d, fname)) for d in SOURCE_DIRS):
                fail(f"node {n['id']!r} names {fname!r}, which does not exist in src/ or include/recon/")
        nodes[n["id"]] = n
    edges = set()
    for e in m["edges"]:
        for end in (e["from"], e["to"]):
            if end not in nodes:
                fail(f"edge {e['from']}->{e['to']} references unknown node {end!r}")
        edges.add((e["from"], e["to"]))
    for fl in m["flows"]:
        for a, b in zip(fl["steps"], fl["steps"][1:]):
            if a not in nodes or b not in nodes:
                fail(f"flow {fl['id']!r} references an unknown node ({a!r} or {b!r})")
            if (a, b) not in edges:
                fail(f"flow {fl['id']!r}: step {a!r} -> {b!r} is not a declared edge")
    return m, lanes, nodes


def q(s):  # safe inside a double-quoted mermaid label
    return s.replace('"', "#quot;")


def generate(m, lanes, nodes):
    out = [f"**{m['summary']}**", "", f"*{m['basis']}*", "", "### Diagram", "", "```mermaid", "flowchart LR"]
    for lane in m["lanes"]:
        out.append(f'  subgraph lane_{lane["id"]}["{q(lane["label"])}"]')
        for n in (x for x in m["nodes"] if x["lane"] == lane["id"]):
            label = q(n["label"]) + (f'<br/>{q(n["file"])}' if n.get("file") else "")
            shape = f'[("{label}")]' if n.get("kind") == "store" else f'["{label}"]'
            out.append(f'    {n["id"]}{shape}')
        out.append("  end")
    for e in m["edges"]:
        arrow = "-.->" if e.get("kind") == "optional" else "-->"
        lab = f'|"{q(e["label"])}"|' if e.get("label") else ""
        out.append(f'  {e["from"]} {arrow}{lab} {e["to"]}')
    out += ["```", "", "Dashed arrows are optional paths. Cylinders are data stores.", "", "### Components by stage", ""]
    for lane in m["lanes"]:
        members = [n for n in m["nodes"] if n["lane"] == lane["id"]]
        out += [f"#### {lane['label']}", "", "| Component | File | What it does | Notes |", "|---|---|---|---|"]
        for n in members:
            files = ", ".join(f"`{x.strip()}`" for x in n.get("file", "").split(",") if x.strip()) or "—"
            notes = "<br>".join("• " + x for x in n.get("notes", [])) or "—"
            name = n["label"] + (" *(data store)*" if n.get("kind") == "store" else "")
            out.append(f"| **{name}** | {files} | {n['desc']} | {notes} |")
        out.append("")
    out += ["### Flows", ""]
    for fl in m["flows"]:
        out.append(f"#### {fl['title']}")
        out.append("")
        out.append(" → ".join(nodes[s]["label"] for s in fl["steps"]))
        out.append("")
        for i, s in enumerate(fl["steps"], 1):
            n = nodes[s]
            out.append(f"{i}. **{n['label']}**" + (f" (`{n['file']}`)" if n.get("file") else "") + f" — {n['desc']}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main():
    check = "--check" in sys.argv[1:]
    m, lanes, nodes = load_and_validate()
    block = f"{BEGIN}\n{generate(m, lanes, nodes)}{END}"
    with open(DOC, encoding="utf-8") as f:
        text = f.read()
    if BEGIN not in text or END not in text:
        fail(f"{os.path.relpath(DOC, ROOT)} is missing the generated-section markers")
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    new = head + block + tail
    if check:
        if new != text:
            fail("docs/ARCHITECTURE.md is out of date: run `python3 scripts/gen_architecture.py`")
        print("architecture map OK: consistent with the source tree, ARCHITECTURE.md is up to date")
        return
    with open(DOC, "w", encoding="utf-8") as f:
        f.write(new)
    print(f"updated {os.path.relpath(DOC, ROOT)} ({len(m['nodes'])} components, {len(m['edges'])} edges, {len(m['flows'])} flows)")


if __name__ == "__main__":
    main()
