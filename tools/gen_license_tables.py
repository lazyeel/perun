#!/usr/bin/env python3
"""Generate the third-party licence inventory in RESEARCH.md § 8.1 and NOTICE.

Neither file is hand-maintained any more: both carry a complete, machine-read
inventory of the crates that reach the distributed object, so a new
`cargo update` cannot silently add a dependency that no notice names.

    python3 tools/gen_license_tables.py           # rewrite both files
    python3 tools/gen_license_tables.py --check   # exit 1 if the files drifted

Method
------
`cargo metadata --filter-platform` resolves the graph for the target triple
only, so a crate that exists purely for another platform cannot appear in a
notice about the Linux binary. The runtime set is then every package reachable
from a workspace member along **normal** edges — not build, not dev — which is
precisely what cargo compiles into the object form. Proc-macro crates are split
out, because their own code never links; only the code they *generate* does,
which is why `linkme-impl` is kept on the runtime side by explicit convention
and everything else that is macro machinery goes to the compile-time side.

Licenses are taken from each package's `license` field, i.e. from the manifest
cargo resolved, never from a website or from memory. An `OR` is a choice the
distributor resolves, and this project resolves it to `MIT` whenever MIT is one
of the terms, so the License column states the licence perun actually takes
rather than the disjunction it chose from; `AND` is a requirement and is never
collapsed. The upstream expression stays in each crate's own manifest, and
`--check` prints both.

The `Role` column is the one part that is not derivable. Roles for the crates
this project uses directly are written out in ROLES below; everything else is
described mechanically as the transitive of whichever direct dependency pulls
it in, which is a fact rather than an opinion.
"""
import json
import re
import subprocess
import sys

REPO = "/opt/data/perun"
TARGET = "x86_64-unknown-linux-gnu"

# Prose that cannot be derived from metadata. Everything not listed here gets a
# mechanical role: "transitive under <the direct dependency that pulls it in>".
ROLES = {
    "libc": "host libc ABI: mmap, sigaction, ucontext, wait4",
    "linkme": "`distributed_slice` — the shim-table registration macro; the "
              "emitted linker sections and runtime slices land in the binary",
    "linkme-impl": "proc macro for `linkme`; the code it generates is linked in",
    "bzip2-rs": "pure-Rust bzip2 decoder in the first-run asset fetcher",
    "ureq": "HTTP client for the Store lane and the asset fetcher, replacing "
            "the external curl binary",
    "cookie_store": "the netscape-format jar behind the shared `mz_at0` store "
                    "session; same version ureq pins, so the `Cookie` it "
                    "returns is that crate's type",
    "flate2": "the bzip2 decoder's DEFLATE half, for callers that need gzip",
    "cookie": "the `Cookie` type cookie_store's jar is built from",
    "getrandom": "OS entropy for the account vault's salt and the SAP signature",
    "ring": "crypto primitives under rustls: SHA-256, HMAC, AES-GCM, ECDSA",
    "rustls": "TLS 1.2/1.3 for every App Store and CDN connection",
    "rustls-webpki": "certificate chain verification under rustls",
    "webpki-roots": "the compiled Mozilla root store rustls anchors against",
    "http": "the HTTP/1.1 message model under ureq",
    "idna": "IDNA/punycode for the internationalised hosts in the API URLs",
    "icu_normalizer_data": "the Unicode normalisation tables `idna` needs",
    "icu_properties_data": "the Unicode property tables `idna` needs",
    "miniz_oxide": "the DEFLATE decompressor under flate2",
    "bzip2": "the bzip2 backend under flate2",
}

# Where the manifest has no `authors` field, the crate's own name for its
# holder is used rather than a guess at a person or an organisation's legal
# entity. Only libc is overridden, to keep the existing wording.
HOLDERS = {"libc": "The Rust Project"}

# A licence expression made only of these terms needs no note in the summary.
PERMISSIVE = {"MIT", "Apache-2.0", "Zlib", "BSD-3-Clause", "ISC", "0BSD",
              "Unlicense"}


def _split(expr, word):
    """Split on `word` at parenthesis depth 0."""
    out, depth, cur, i = [], 0, "", 0
    while i < len(expr):
        if depth == 0 and expr.startswith(word, i):
            out.append(cur)
            cur = ""
            i += len(word)
            continue
        if expr[i] == "(":
            depth += 1
        elif expr[i] == ")":
            depth -= 1
        cur += expr[i]
        i += 1
    out.append(cur)
    return [p.strip() for p in out]


def _unwrap(expr):
    """Drop one layer of parentheses that wraps the whole expression.

    A group like `(MIT OR Apache-2.0)` is at depth 1 throughout, so splitting
    it without unwrapping first would miss the `OR` inside it — and a group
    that keeps its parentheses would survive verbatim, which is how
    `(MIT OR Apache-2.0) AND Unicode-3.0` used to come out wrong.
    """
    s = expr.strip()
    while len(s) > 1 and s[0] == "(" and s[-1] == ")":
        depth = 0
        balanced = True
        for i, c in enumerate(s):
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0 and i != len(s) - 1:
                    balanced = False  # the '(' that opens is not the last ')'s
                    break
        if not balanced:
            break
        s = s[1:-1].strip()
    return s


def select_license(expr):
    """The one licence perun takes, given the upstream SPDX expression.

    `OR` is a choice, not a requirement. `MIT OR Apache-2.0` is a disjunction
    the distributor resolves, and perun resolves it to `MIT` — the most
    permissive term in the set, and the one every consumer of a NOTICE expects
    to be able to comply with on its own. The legacy `MIT/Apache-2.0` spelling
    is the same disjunction and is handled the same way.

    `AND` is a requirement and is never collapsed. `Apache-2.0 AND ISC`
    obliges both terms and stays as it is, and `(MIT OR Apache-2.0) AND
    Unicode-3.0` reduces to `MIT AND Unicode-3.0` — the choice inside the
    group is resolved, the requirement around it is not. Reducing that one to
    `MIT` would drop a copyleft obligation, which is the one mistake this
    function must not be able to make.
    """
    if not expr:
        return expr
    conjuncts = []
    for group in _split(expr.replace("/", " OR "), " AND "):
        # Unwrap the group *before* splitting it: a group written
        # `(MIT OR Apache-2.0)` keeps its `OR` at depth 1, so splitting first
        # would yield one opaque option and never see the choice inside.
        options = [o for o in (_unwrap(o) for o in _split(_unwrap(group), " OR ")) if o]
        if "MIT" in options:
            conjuncts.append("MIT")
        elif len(options) == 1:
            conjuncts.append(options[0])
        else:
            conjuncts.append(" OR ".join(options))
    return " AND ".join(conjuncts)

BEGIN = "<!-- BEGIN GENERATED: {name} -->"
END = "<!-- END GENERATED: {name} -->"


def metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--filter-platform", TARGET],
        cwd=REPO, capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def built_crates():
    """The crates rustc is actually invoked for, as `{(name, version): proc_macro}`.

    `cargo metadata`'s resolve graph is a superset: it keeps the *optional*
    dependencies of a package that no enabled feature asks for. Dropping
    ureq's `cookies` feature therefore still leaves `cookie_store`, `url`,
    `idna` and the ICU4X slice in that graph — and in Cargo.lock — while the
    compiler never touches them. `cargo tree` agrees with `cargo build -v`, so
    the build graph is the only honest answer to "is this in the object form",
    and it is what decides the two tables.
    """
    out = subprocess.run(
        ["cargo", "tree", "-e", "normal", "--prefix", "none", "--format", "{p}"],
        cwd=REPO, capture_output=True, text=True, check=True)
    built = {}
    for line in out.stdout.splitlines():
        line = line.strip()
        if line.endswith(" (*)"):
            line = line[: -len(" (*)")]
        if " " not in line:
            continue
        macro = line.endswith(" (proc-macro)")
        if macro:
            line = line[: -len(" (proc-macro)")]
        name, _, version = line.rpartition(" ")
        version = version.removeprefix("v")  # `{p}` spells versions `v0.1.2`
        if not name or not version[:1].isdigit():
            continue  # a path, not a package
        built[(name, version)] = macro
    return built


def is_proc_macro(pkg):
    return any("proc-macro" in t["kind"] for t in pkg["targets"])


def by_id(md):
    return {p["id"]: p for p in md["packages"]}


def graph(md):
    """nodes: id -> list of (dep_id, kind). kind None means the default, normal."""
    g = {}
    for node in md["resolve"]["nodes"]:
        edges = []
        for dep in node["deps"]:
            kinds = {dk["kind"] for dk in dep.get("dep_kinds", [])}
            if not kinds:
                kinds = {None}
            for k in kinds:
                edges.append((dep["pkg"], k))
        g[node["id"]] = edges
    return g


def reach(md, g, roots, want, ids, stop_at_proc_macro=False):
    """Shortest path from any root to each reachable id, following `want` kinds.

    `stop_at_proc_macro` refuses to descend into a proc-macro package, which
    is the whole discriminator between the two groups: `proc-macro2`, `quote`
    and `syn` are ordinary `lib` targets, so cargo reports no distinguishing
    kind for them, and the only fact that matters is that nothing on the path
    to them but rustc ever runs. A crate reachable without stepping through a
    proc-macro crate has its code in the linked object; one that is not, does
    not.
    """
    best, queue = {}, [(r, (r,)) for r in roots]
    while queue:
        node, path = queue.pop(0)
        if node in best:
            continue
        best[node] = path
        for dep, kind in g.get(node, []):
            if kind not in want or dep in best:
                continue
            if stop_at_proc_macro and is_proc_macro(ids[dep]):
                continue
            queue.append((dep, path + (dep,)))
    return best


def direct_ancestor(path, ids, members):
    """The first non-workspace package along the path: what pulled it in."""
    for pid in path[1:]:
        if pid not in members:
            return ids[pid]["name"]
    return ids[path[-1]]["name"]


def repo_url(pkg):
    url = pkg.get("repository") or ""
    url = re.sub(r"^git\+", "", url)
    url = url.split("#")[0]
    return url


def holder(pkg):
    if pkg["name"] in HOLDERS:
        return HOLDERS[pkg["name"]]
    # Strip the e-mail from `Name <mail>`: the address is not part of an
    # attribution line, and the existing NOTICE entries name people only.
    authors = [re.sub(r"\s*<[^>]*>\s*$", "", a).strip()
               for a in (pkg.get("authors") or [])]
    authors = [a for a in authors if a]
    if authors:
        return ", ".join(authors)
    url = repo_url(pkg)
    if "github.com/" in url:
        return url.split("github.com/", 1)[1].rstrip("/")
    return url or "—"


def author_repo(pkg):
    """The `Author / repository` column: holder, then the repository in parens."""
    h, url = holder(pkg), repo_url(pkg)
    tail = url.split("github.com/", 1)[1].rstrip("/") if "github.com/" in url else None
    if not h or h == "—":
        return tail or "—"
    if tail and tail != h:
        return f"{h} ({tail})"
    return h


def role(pkg, path, ids, members):
    if pkg["name"] in ROLES:
        return ROLES[pkg["name"]]
    return f"transitive under {direct_ancestor(path, ids, members)}"


def build():
    md = metadata()
    ids, g, members = by_id(md), graph(md), set(md["workspace_members"])
    NORMAL = {None, "normal"}
    everything = reach(md, g, members, NORMAL, ids)
    linked = reach(md, g, members, NORMAL, ids, stop_at_proc_macro=True)
    via_build = reach(md, g, members, {"build"}, ids)
    # Narrow both to the build graph: the resolve graph carries optional
    # dependencies no enabled feature asks for, and calling those "in the
    # object form" would be wrong.
    built = built_crates()

    def is_built(pid):
        p = ids[pid]
        return (p["name"], p["version"]) in built

    OURS = ("perun-core", "perun-shims", "perun-cli")
    runtime, compiletime = {}, {}
    for pid in linked:
        if ids[pid]["name"] not in OURS and is_built(pid):
            runtime[pid] = everything[pid]
    # `linkme-impl` is a proc macro, but the statics and sections it generates
    # are what put the shim table in the binary, so it is attributed on the
    # runtime side by project convention rather than by the reachability rule.
    for pid, pkg in ids.items():
        if pkg["name"] == "linkme-impl" and pid in everything and is_built(pid):
            runtime[pid] = everything[pid]
    for pid in everything:
        if pid in runtime or ids[pid]["name"] in OURS or not is_built(pid):
            continue
        compiletime[pid] = everything[pid]
    # Anything only a build script reaches is compile-time as well.
    for pid in via_build:
        if pid not in runtime and is_built(pid) and ids[pid]["name"] not in OURS:
            compiletime.setdefault(pid, everything.get(pid, (pid,)))

    def rows(pids):
        out = []
        for pid in pids:
            pkg = ids[pid]
            out.append((pkg["name"], pkg["version"], select_license(pkg["license"]),
                        author_repo(pkg), role(pkg, everything[pid], ids, members),
                        repo_url(pkg) or "—"))
        return sorted(out, key=lambda r: r[0])

    return sorted(rows(runtime)), sorted(rows(compiletime))


def licence_summary(rt):
    """Every distinct licence expression on the runtime side, verbatim."""
    seen = {}
    for row in rt:
        seen.setdefault(row[2], []).append(row[0])
    return seen


def notice_line(name, version, lic, hold, url):
    return f"- {name} {version} ({lic}) — {hold} — {url}"


def research_block(rt, ct):
    L = [BEGIN.format(name="license-tables")]
    L.append(f"**Runtime — compiled into the `perun` ELF ({len(rt)} crates):**")
    L.append("")
    L.append("| Crate | Version | License | Author / repository | Role |")
    L.append("|---|---|---|---|---|")
    for n, v, lic, ar, ro, _u in rt:
        L.append(f"| `{n}` | {v} | {lic} | {ar} | {ro} |")
    L.append("")
    L.append(f"**Compile-time only — executed by rustc during the build, "
             f"absent from the binary ({len(ct)} crates):**")
    L.append("")
    L.append("| Crate | Version | License | Author / repository |")
    L.append("|---|---|---|---|")
    for n, v, lic, ar, _r, _u in ct:
        L.append(f"| `{n}` | {v} | {lic} | {ar} |")
    L.append("")
    L.append(END.format(name="license-tables"))
    return "\n".join(L)


def notice_block(rt, ct):
    L = [BEGIN.format(name="license-notice")]
    L.append("This product contains third-party open source software in object "
             "form, under its own license:")
    L.append("")
    for n, v, lic, ar, _r, url in rt:
        # The holder is a name for a person or an org; the URL is the
        # repository itself. Re-deriving the URL by parsing the holder string
        # loses it exactly for the crates whose holder *is* the repo slug.
        hold = ar[: ar.rindex(" (")] if " (" in ar else ar
        L.append(notice_line(n, v, lic, hold, url))
    L.append("")
    L.append("Build-time only, and therefore absent from the distributed object: "
         + ", ".join(f"`{row[0]}` {row[1]}" for row in ct) + ".")
    L.append("")
    L.append("`linkme-impl` is a proc macro, but the code it generates is "
             "compiled into the binaries, so it is listed above.")
    L.append(END.format(name="license-notice"))
    return "\n".join(L)


def splice(path, name, block):
    text = open(path).read()
    b, e = BEGIN.format(name=name), END.format(name=name)
    if b not in text or e not in text:
        raise SystemExit(f"{path}: markers for {name} not found")
    pre = text[: text.index(b)]
    post = text[text.index(e) + len(e):]
    return pre + block + post, text == pre + block + post


def main():
    check = "--check" in sys.argv
    rt, ct = build()
    lic = licence_summary(rt)

    research = research_block(rt, ct)
    notice = notice_block(rt, ct)

    ok = True
    for path, name, block in (
        (f"{REPO}/RESEARCH.md", "license-tables", research),
        (f"{REPO}/NOTICE", "license-notice", notice),
    ):
        new, unchanged = splice(path, name, block)
        if check:
            if unchanged:
                print(f"{path}: up to date")
            else:
                print(f"{path}: DRIFTED")
                ok = False
        else:
            open(path, "w").write(new)
            print(f"{path}: rewritten ({'unchanged' if unchanged else 'updated'})")

    print(f"\nruntime crates: {len(rt)}   compile-time crates: {len(ct)}")
    print("licences as reported (selected <- upstream where they differ):")
    for expr, names in sorted(lic.items(), key=lambda kv: -len(kv[1])):
        tag = "permissive-only" if all(
            t.strip("()") in PERMISSIVE
            for t in re.split(r"\s+(?:OR|AND)\s+", expr.replace("/", " OR "))
        ) else "NEEDS ATTENTION"
        print(f"  {len(names):3d}  {expr:30s} {tag}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
