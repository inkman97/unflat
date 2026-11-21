import argparse
import sys
from collections import Counter

from . import __version__, cfg, patcher, scan, vm
from .code import Code, discover_functions
from .explorer import Explorer
from .image import Image
from .resolver import Resolver

MODES = ("scan", "flat", "vm")


def parse_args(argv):
    p = argparse.ArgumentParser(prog="unflat", description="Static helpers for obfuscated x64 code (Windows PE and Linux ELF).")
    p.add_argument("--version", action="version", version=f"unflat {__version__}")
    sub = p.add_subparsers(dest="mode", required=True)

    s = sub.add_parser("scan", help="detect control-flow flattening and bytecode VM dispatchers, per function")
    s.add_argument("input", help="x64 PE or x86-64 ELF file")
    s.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    s.add_argument("-v", "--verbose", action="store_true", help="list every flagged function and every function with indirect jumps")

    f = sub.add_parser("flat", help="resolve and patch out register-indirect dispatchers (control-flow flattening)")
    f.add_argument("input", help="x64 PE (exe/dll, or a pe-sieve dump) or x86-64 ELF (executable, PIE, shared object)")
    f.add_argument("-o", "--output", help="write a patched copy with dispatchers replaced by direct jumps")
    f.add_argument("-l", "--listing", help="write a text listing that follows the recovered control flow")
    f.add_argument("-d", "--dot", help="write the recovered control flow graph in Graphviz DOT format")
    f.add_argument("-f", "--function", action="append", type=lambda s: int(s, 0), default=[],
                   help="entry point to use for listing/dot (repeatable); default: every function")
    f.add_argument("--limit", type=int, default=4000, help="instructions to scan backwards for constant registers")
    f.add_argument("--steps", type=int, default=50000, help="maximum blocks explored per function")
    f.add_argument("-v", "--verbose", action="store_true", help="print every dispatcher")

    v = sub.add_parser("vm", help="trace a virtualized function: dispatcher, handlers, bytecode and virtual program")
    v.add_argument("input", help="x64 PE or x86-64 ELF file")
    v.add_argument("-e", "--entry", required=True, help="address, export name (PE) or symbol name (ELF) of the function that runs the VM")
    v.add_argument("-a", "--arg", action="append", type=lambda s: int(s, 0), default=[],
                   help="integer argument (repeatable): rcx, rdx, r8, r9 for PE; rdi, rsi, rdx, rcx, r8, r9 for ELF")
    v.add_argument("-n", "--max", type=int, default=2_000_000, help="maximum native instructions to emulate")
    v.add_argument("-o", "--output", help="write the report to a file instead of stdout")

    if argv and argv[0] not in MODES and not argv[0].startswith("-"):
        argv = ["flat", *argv]
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    image = Image.load(args.input)
    code = Code(image)
    if not image.functions:
        image.functions = discover_functions(image, code)
    return {"scan": run_scan, "vm": run_vm, "flat": run_flat}[args.mode](args, image, code)


def run_scan(args, image, code):
    results = scan.scan(image, code)
    if args.output:
        with open(args.output, "w") as out:
            scan.report(image, code, results, out, args.verbose)
        print(f"report -> {args.output}")
    else:
        scan.report(image, code, results, sys.stdout, args.verbose)
    return 0


def run_vm(args, image, code):
    entry = _entry(image, args.entry)
    tracer = vm.Tracer(image, code, args.max).run(entry, args.arg)
    analysis = vm.VMAnalysis(tracer)
    if args.output:
        with open(args.output, "w") as out:
            vm.report(analysis, out)
        print(f"report -> {args.output}")
    else:
        vm.report(analysis, sys.stdout)
    return 0


def _entry(image, value):
    try:
        return int(value, 0)
    except ValueError:
        if value in image.symbols:
            return image.symbols[value]
    raise SystemExit(f"entry not found: {value}")


def run_flat(args, image, code):
    resolver = Resolver(image, code, args.limit)
    dispatches = [resolver.resolve(d) for d in resolver.find()]
    explorer = Explorer(resolver, max_steps=args.steps)
    explorer.register(dispatches)
    for start, end in sorted({image.function_of(d.jmp) for d in dispatches} - {None}):
        explorer.explore(start, (start, end))
    explorer.apply(dispatches)
    for d in dispatches:
        if d.status == "unresolved" and resolver.is_switch(d):
            d.status = "switch"
    by_jmp = {d.jmp: d for d in dispatches}
    edges = {d.jmp: d.targets for d in dispatches if d.targets}

    reachable = set()
    for start, end in image.functions:
        for insns, _ in cfg.walk(code, start, edges, (start, end)).values():
            reachable.update(insns)

    stats = Counter(d.status for d in dispatches)
    live = Counter(d.status for d in dispatches if d.jmp in reachable)
    print(f"{args.input}: {len(code.addrs)} instructions, {len(image.functions)} functions")
    print(f"dispatchers: {len(dispatches)} ({sum(live.values())} reachable from a function entry)")
    for status in ("cond", "goto", "context", "switch", "unresolved"):
        print(f"  {status:<11} {stats[status]:>5}   reachable: {live[status]}")
    print(f"  opaque predicates removed: {sum(d.opaque for d in dispatches)}")
    if args.verbose:
        for d in dispatches:
            tgt = ", ".join(f"{t:#x}" for t in d.targets) or "-"
            flag = "" if d.jmp in reachable else "  (not reached)"
            print(f"  {d.jmp:#x} jmp {d.reg:<4} {d.status:<10} {tgt}{'  opaque' if d.opaque else ''}{flag}")
    print(f"reachable instructions from function entries: {cfg.coverage(code, image.functions, {})} -> {len(reachable)}")

    if args.output:
        patched, skipped = patcher.apply(image, code, dispatches)
        with open(args.output, "wb") as f:
            f.write(image.raw)
        print(f"patched {len(patched)} dispatchers ({len(skipped)} resolved but not patchable) -> {args.output}")

    if args.listing or args.dot:
        bounds = {f[0]: f for f in image.functions}
        graphs = [(e, cfg.walk(code, e, edges, bounds.get(e))) for e in args.function or bounds]
        if args.listing:
            with open(args.listing, "w") as out:
                for e, blocks in graphs:
                    out.write(f"\n;; ===== function {e:#x} ({len(blocks)} blocks) =====\n")
                    cfg.listing(code, blocks, by_jmp, out)
            print(f"listing -> {args.listing}")
        if args.dot:
            merged = {}
            for _, blocks in graphs:
                merged.update(blocks)
            with open(args.dot, "w") as out:
                cfg.dot(merged, by_jmp, out)
            print(f"dot -> {args.dot}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
