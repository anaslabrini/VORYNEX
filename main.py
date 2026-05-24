from vorynex import vertex, vortex
import os
import sys
import platform
import datetime
import traceback
import socket
import ctypes

# ── Color primitives ──────────────────────────────────────────────────────────
class C:
    RST   = "\033[0m"
    BOLD  = "\033[1m"
    DIM   = "\033[2m"
    CYN   = "\033[96m"
    BLU   = "\033[94m"
    GRN   = "\033[92m"
    YLW   = "\033[93m"
    RED   = "\033[91m"
    WHT   = "\033[97m"
    BCYN  = "\033[96m\033[1m"
    BRED  = "\033[91m\033[1m"
    BGRN  = "\033[92m\033[1m"
    BYLW  = "\033[93m\033[1m"

def _c(code, text): return f"{code}{text}{C.RST}"

def cyn(t):  return _c(C.CYN,  t)
def blu(t):  return _c(C.BLU,  t)
def grn(t):  return _c(C.GRN,  t)
def ylw(t):  return _c(C.YLW,  t)
def red(t):  return _c(C.RED,  t)
def wht(t):  return _c(C.WHT,  t)
def dim(t):  return _c(C.DIM,  t)
def bld(t):  return _c(C.BOLD, t)
def bcyn(t): return _c(C.BCYN, t)
def bred(t): return _c(C.BRED, t)
def bgrn(t): return _c(C.BGRN, t)
def bylw(t): return _c(C.BYLW, t)

# ── Constants ─────────────────────────────────────────────────────────────────
FRAMEWORK_NAME    = "VORYNEX"
FRAMEWORK_VERSION = "2.0.0"
FRAMEWORK_AUTHOR  = "Anas Labrini"
FRAMEWORK_TAGLINE = "Enterprise Exposure Intelligence Framework"

TOOL_META = {
    "1": {
        "name":        "VERTEX",
        "version":     "1.0.0",
        "author":      "Anis El Brini",
        "full_name":   "Visual Exposure & Risk Topology EXaminer",
        "scope":       "Network + Endpoint",
        "platform":    "Windows / Linux / macOS (degraded)",
        "output":      "HTML + JSON + LOG",
        "stages":      9,
        "description": "Multi-stage network topology mapper, service scanner, identity auditor, and hardening inspector with correlated risk scoring.",
    },
    "2": {
        "name":        "VORTEX",
        "version":     "2.0.0",
        "author":      "Anas Labrini",
        "full_name":   "Vulnerability & Operational Risk Telemetry EXtraction",
        "scope":       "Deep Endpoint Intelligence",
        "platform":    "Windows only",
        "output":      "HTML + JSON + LOG",
        "stages":      11,
        "description": "11-domain Windows endpoint intelligence engine. Collects credentials surface, persistence mechanisms, process intel, security telemetry and correlates into multi-axis risk profile.",
    },
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def pause():
    print()
    input(dim("  Press Enter to return to menu..."))

def _is_elevated() -> bool:
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.getuid() == 0
    except Exception:
        return False

def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"

def _get_os_label() -> str:
    s = platform.system()
    if s == "Windows":
        return f"Windows {platform.release()} ({platform.version()})"
    elif s == "Darwin":
        return f"macOS {platform.mac_ver()[0]}"
    else:
        return f"{s} {platform.release()}"

def _sep(char="─", width=72, color=C.DIM):
    return _c(color, char * width)

def _header_line(title: str, color=C.BCYN):
    bar = _sep("━", 72, C.CYN)
    print(f"\n{bar}")
    print(f"  {_c(color, title)}")
    print(bar)

# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = r"""
  ██╗   ██╗ ██████╗ ██████╗ ██╗   ██╗███╗   ██╗███████╗██╗  ██╗
  ██║   ██║██╔═══██╗██╔══██╗╚██╗ ██╔╝████╗  ██║██╔════╝╚██╗██╔╝
  ██║   ██║██║   ██║██████╔╝ ╚████╔╝ ██╔██╗ ██║█████╗   ╚███╔╝
  ╚██╗ ██╔╝██║   ██║██╔══██╗  ╚██╔╝  ██║╚██╗██║██╔══╝   ██╔██╗
   ╚████╔╝ ╚██████╔╝██║  ██║   ██║   ██║ ╚████║███████╗██╔╝ ██╗
    ╚═══╝   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝"""

def _print_banner():
    print(bcyn(BANNER))
    print()
    print(f"  {dim('━' * 68)}")
    print(f"  {wht(FRAMEWORK_TAGLINE):<40}  {dim(f'v{FRAMEWORK_VERSION}')}  {dim('|')}  {dim(f'By {FRAMEWORK_AUTHOR}')}")
    print(f"  {dim('━' * 68)}")

# ── System info panel ─────────────────────────────────────────────────────────
def _print_sysinfo():
    now       = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    hostname  = _hostname()
    os_label  = _get_os_label()
    user      = os.environ.get("USERNAME", os.environ.get("USER", "unknown"))
    elevated  = bgrn("ELEVATED") if _is_elevated() else ylw("STANDARD")
    py_ver    = platform.python_version()

    print()
    print(f"  {dim('Session')}    {wht(now)}   {dim('|')}   {dim('Host')}  {wht(hostname)}")
    print(f"  {dim('Platform')}   {wht(os_label)}")
    print(f"  {dim('User')}       {wht(user)}   {dim('|')}   {dim('Privilege')}  {elevated}   {dim('|')}   {dim('Python')}  {wht(py_ver)}")
    print()

# ── Warning banner ────────────────────────────────────────────────────────────
def _print_legal():
    print(f"  {bred('WARNING')}  {dim('This framework is for authorized security assessments only.')}")
    print(f"  {dim('Unauthorized use is prohibited and may be subject to criminal prosecution.')}")
    print()

# ── Tool cards ────────────────────────────────────────────────────────────────
def _print_menu():
    print(f"  {_sep('─', 68, C.DIM)}")
    print(f"  {dim('AVAILABLE ENGINES')}")
    print(f"  {_sep('─', 68, C.DIM)}")
    print()

    for key, meta in TOOL_META.items():
        badge   = bcyn(f"  [{key}]")
        name    = bld(wht(f"{meta['name']}"))
        version = dim(f"v{meta['version']}")
        scope   = cyn(meta['scope'])
        plat    = dim(meta['platform'])
        stages  = dim(f"{meta['stages']} {'stages' if meta['name'] == 'VERTEX' else 'domains'}")
        out     = dim(meta['output'])
        desc    = meta['description']

        print(f"{badge}  {name}  {version}")
        print(f"       {dim(meta['full_name'])}")
        print(f"       {dim('Scope')}     {scope}   {dim('|')}  {plat}")
        print(f"       {dim('Pipeline')}  {stages}  {dim('|')}  Output: {out}")
        print(f"       {dim(desc[:80])}")
        print()

    print(f"  {_sep('─', 68, C.DIM)}")
    print(f"  {dim('[0]')}  Exit framework")
    print(f"  {_sep('─', 68, C.DIM)}")
    print()

# ── Pre-launch confirmation ───────────────────────────────────────────────────
def _confirm_launch(meta: dict) -> bool:
    name    = meta['name']
    plat    = meta['platform']
    version = meta['version']
    author  = meta['author']

    print()
    print(f"  {_sep('─', 68, C.CYN)}")
    print(f"  {bcyn('LAUNCH CONFIRMATION')}")
    print(f"  {_sep('─', 68, C.CYN)}")
    print()
    print(f"  {dim('Engine')}      {wht(name)}  {dim(f'v{version}')}  {dim(f'by {author}')}")
    print(f"  {dim('Full name')}   {dim(meta['full_name'])}")
    print(f"  {dim('Scope')}       {cyn(meta['scope'])}")
    print(f"  {dim('Platform')}    {dim(plat)}")
    print(f"  {dim('Output')}      {dim(meta['output'])}")
    print()

    # Platform check
    current_os = platform.system()
    if name == "VORTEX" and current_os != "Windows":
        print(f"  {bred('INCOMPATIBLE PLATFORM')}  VORTEX requires Windows.")
        print(f"  {dim(f'Detected: {current_os}. All registry-based domains will fail.')} ")
        print()

    if not _is_elevated():
        print(f"  {bylw('PRIVILEGE NOTICE')}  Running as standard user.")
        print(f"  {dim('Some domains may return partial data or be skipped.')}")
        print()

    try:
        confirm = input(f"  {dim('Proceed?')}  {wht('[Y/n]')}  > ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return False

    return confirm in ("", "y", "yes")

# ── Tool runner ───────────────────────────────────────────────────────────────
def _run_tool(tool_function, meta: dict):
    name = meta['name']

    if not _confirm_launch(meta):
        print(f"\n  {ylw('[CANCELLED]')}  Launch aborted by operator.")
        pause()
        return

    clear()
    start = datetime.datetime.now()

    print()
    print(f"  {_sep('━', 68, C.CYN)}")
    _ver = meta['version']
    print(f"  {bcyn('INITIALIZING')}  {wht(name)}  {dim('v' + _ver)}")
    print(f"  {_sep('━', 68, C.CYN)}")
    print(f"  {dim('Start time')}   {wht(start.strftime('%Y-%m-%d %H:%M:%S'))}")
    print(f"  {dim('Host')}         {wht(_hostname())}")
    print(f"  {dim('Privilege')}    {bgrn('ELEVATED') if _is_elevated() else ylw('STANDARD')}")
    print(f"  {_sep('━', 68, C.CYN)}")
    print()

    try:
        tool_function()

    except KeyboardInterrupt:
        elapsed = round((datetime.datetime.now() - start).total_seconds(), 1)
        print()
        print(f"  {_sep('─', 68, C.YLW)}")
        print(f"  {bylw('INTERRUPTED')}  {name} was stopped by operator.")
        print(f"  {dim('Elapsed')}  {wht(f'{elapsed}s')}  {dim('|')}  Partial output may have been saved.")
        print(f"  {_sep('─', 68, C.YLW)}")

    except ImportError as e:
        print()
        print(f"  {_sep('─', 68, C.RED)}")
        print(f"  {bred('IMPORT ERROR')}  A required module is not available.")
        print(f"  {dim('Details')}    {wht(str(e))}")
        print()
        if "winreg" in str(e).lower():
            print(f"  {ylw('Cause')}      VORTEX requires Windows. winreg is not available on {platform.system()}.")
        elif "psutil" in str(e).lower():
            print(f"  {ylw('Cause')}      psutil is not installed.")
            print(f"  {dim('Fix')}        Run: {wht('pip install psutil')}")
        print(f"  {_sep('─', 68, C.RED)}")

    except PermissionError as e:
        print()
        print(f"  {_sep('─', 68, C.RED)}")
        print(f"  {bred('PERMISSION DENIED')}  Insufficient privileges.")
        print(f"  {dim('Details')}    {wht(str(e))}")
        print(f"  {ylw('Fix')}        Re-run the framework as Administrator / root.")
        print(f"  {_sep('─', 68, C.RED)}")

    except FileNotFoundError as e:
        print()
        print(f"  {_sep('─', 68, C.RED)}")
        print(f"  {bred('FILE NOT FOUND')}  A required resource is missing.")
        print(f"  {dim('Details')}    {wht(str(e))}")
        print(f"  {_sep('─', 68, C.RED)}")

    except OSError as e:
        print()
        print(f"  {_sep('─', 68, C.RED)}")
        print(f"  {bred('OS ERROR')}  {wht(str(e))}")
        print(f"  {dim('Code')}       {wht(str(e.errno))}")
        print(f"  {_sep('─', 68, C.RED)}")

    except Exception as e:
        elapsed = round((datetime.datetime.now() - start).total_seconds(), 1)
        exc_type = type(e).__name__
        print()
        print(f"  {_sep('─', 68, C.RED)}")
        print(f"  {bred('UNHANDLED EXCEPTION')}  {name} terminated unexpectedly.")
        print(f"  {dim('Type')}       {wht(exc_type)}")
        print(f"  {dim('Details')}    {wht(str(e))}")
        print(f"  {dim('Elapsed')}    {wht(f'{elapsed}s')}")
        print(f"  {_sep('─', 68, C.RED)}")
        print()
        print(f"  {dim('Stack trace:')}")
        print(_c(C.DIM, "  " + traceback.format_exc().replace("\n", "\n  ")))
        print(f"  {_sep('─', 68, C.RED)}")

    finally:
        elapsed = round((datetime.datetime.now() - start).total_seconds(), 1)
        print()
        print(f"  {_sep('─', 68, C.DIM)}")
        print(f"  {dim('Engine')}  {wht(name)}  {dim('|')}  {dim('Total time')}  {wht(f'{elapsed}s')}")
        print(f"  {_sep('─', 68, C.DIM)}")
        pause()

# ── Main loop ─────────────────────────────────────────────────────────────────
def _show():
    clear()
    _print_banner()
    _print_sysinfo()
    _print_legal()
    _print_menu()

def main():
    while True:
        try:
            _show()

            try:
                choice = input(f"  {dim('Select engine')}  {wht('[1 / 2 / 0]')}  {dim('>')}  ").strip()
            except EOFError:
                choice = "0"

            if choice == "1":
                _run_tool(vertex.executionstart, TOOL_META["1"])

            elif choice == "2":
                _run_tool(vortex.executionstart, TOOL_META["2"])

            elif choice == "0":
                clear()
                print()
                print(f"  {_sep('─', 68, C.DIM)}")
                print(f"  {cyn(FRAMEWORK_NAME)}  {dim('session terminated.')}")
                print(f"  {dim(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}")
                print(f"  {_sep('─', 68, C.DIM)}")
                print()
                sys.exit(0)

            elif choice.strip() == "":
                pass  # ignore empty input silently

            else:
                print()
                print(f"  {ylw('[INVALID]')}  {wht(repr(choice))}  is not a valid option.")
                print(f"  {dim('Expected: 1, 2, or 0.')}")
                pause()

        except KeyboardInterrupt:
            print()
            print(f"\n  {ylw('[CTRL+C]')}  Use {wht('[0]')} to exit cleanly.")
            pause()

        except Exception as e:
            print()
            print(f"  {bred('FATAL ERROR')}  An unexpected error occurred in the main loop.")
            print(f"  {dim('Type')}       {wht(type(e).__name__)}")
            print(f"  {dim('Details')}    {wht(str(e))}")
            print()
            print(_c(C.DIM, "  " + traceback.format_exc().replace("\n", "\n  ")))
            pause()


if __name__ == "__main__":
    main()