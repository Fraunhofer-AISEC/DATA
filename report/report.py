import argparse
from collections import defaultdict
import glob
from itertools import chain
import pylatex
from pylatex import Command, NewPage, NewLine, NoEscape, Package, Section, Subsection
import sys

from datagui.package.model.LibHierarchyModel import LibHierarchyModel, LibHierarchyItem
from datagui.package import utils
from datagui.package.utils import (
    ErrorCode,
    CustomRole,
    IpInfo,
    info_map,
    LeakMetaInfo,
    ColorScheme,
    LeakFlags,
    debug,
    getCtxName,
    createIconButton,
    register_assert_handler,
    loadipinfo,
    getLogoIcon,
    getLogoIconPixmap,
    getResourceFile,
    registerFonts,
    getDefaultIconSize,
    getIconById,
    getIconColorById,
    getIconTooltipById,
)

from datastub.export import loadpickle
from datastub.IpInfoShort import IP_INFO_FILE, IpInfoShort
from datastub.leaks import (
    Library,
    FunctionLeak,
    NSLeak,
    DataLeak,
    CFLeak,
    CallHistory,
    LibHierarchy,
    Leak,
)
from datastub.utils import sorted_keys

from pylatex_ext import TextColorExt, LstListing


parser = argparse.ArgumentParser(description="DATA Leakage Report Generator")
parser.add_argument("experiment", help="Name of the experiment")
parser.add_argument(
    "pickle", nargs="?", default=None, help="Path to the 'result_phaseX.pickle'"
)
parser.add_argument("zip", nargs="?", default=None, help="Path to the 'framework.zip'")
args = parser.parse_args()

PICKLE = ["result_phase", ".pickle"]
ZIP = "framework.zip"


class LeakOverview:
    def __init__(self, leaks_docs, filter=None):
        if filter is not None:
            leaks_docs = [ld for ld in leaks_docs if isinstance(ld.leak, filter)]
        self.name = "DataLeak & CFLeak" if filter is None else filter.name
        self.count_total = len(leaks_docs)
        self.count_no_leak = LeakOverview._count_leaks_docs(
            LeakFlags.NOLEAK, leaks_docs
        )
        self.count_investigate = LeakOverview._count_leaks_docs(
            LeakFlags.INVESTIGATE, leaks_docs
        )
        self.count_leak = LeakOverview._count_leaks_docs(LeakFlags.LEAK, leaks_docs)

        assert (
            self.count_total
            == self.count_no_leak + self.count_investigate + self.count_leak
        )

    def _count_leaks_docs(leak_flag, leaks_docs):
        count = 0
        for leak_docs in leaks_docs:
            if leak_docs.leak.meta is None:
                leak_docs.leak.meta = LeakMetaInfo()
            if leak_docs.leak.meta.flag != leak_flag:
                continue
            count += 1
        return count

    def print_header(self):
        return [self.name, "No leak", "Investigate", "Leak", "Total"]

    def print_overview(self):
        return [
            "",
            f"{self.count_no_leak}",
            f"{self.count_investigate}",
            f"{self.count_leak}",
            f"{self.count_total}",
        ]


class LeakDump:
    def __init__(self, filename, line, pre_leak, leak, post_leak):
        self.filename = filename
        self.line = line
        self.pre_leak = pre_leak
        self.leak = leak
        self.post_leak = post_leak

        if "DATA" in self.filename:
            tmp = self.filename.split("DATA")
            self.filename = f"DATA{tmp[-1]}"

    def print_tex(self):
        indent = " " * (len(self.leak) - len(self.leak.lstrip(" ")))
        leak = pylatex.TextColor("red", self.leak).dumps()
        leak = f"{indent}§{leak}§"

        return self.pre_leak + [leak] + self.post_leak


class LeakFile:
    def __init__(self, file_path, line, binary_format=False):
        self.file_path = file_path
        self.line = line
        self.binary_format = binary_format

    def open_file(self):
        encoding = None if self.binary_format else "utf-8"
        with utils.datafs.get_file(self.file_path, encoding=encoding) as f:
            dump = f.read()
        return dump


class LeakDocs:
    def __init__(self, lib_name, lib_tree_item, ip, asm, src):
        isinstance(lib_tree_item, LibHierarchyItem)
        self.lib_name = lib_name
        self.fn_name = lib_tree_item.name
        self.ip = ip
        self.asm = asm
        self.src = src
        self.leak = self.filter_leak(
            chain(lib_tree_item.obj.dataleaks, lib_tree_item.obj.cfleaks)
        )

        self.fn_name = " ".join(self.fn_name.split(" ")[1:])
        self.fn_name = "(t)".join(self.fn_name.split("(t)")[:-1])

    def filter_leak(self, leaks):
        leak = [leak for leak in leaks if leak.ip == self.ip]
        assert len(leak) == 1
        return leak[0]

    def __lt__(self, other):
        if (self.src is not None and other.src is not None) and (
            self.src.filename == other.src.filename
        ):
            return self.src.line < other.src.line
        return self.asm.line < other.asm.line


# Copied from data-gui repository
def createLibFunctionItems(lib, parent_item):
    """Create tree items of library function in the lib hierarchy.

    Agrs:
        lib: The library object containing functions
        parent_item: The corresponding library tree item

    Returns:
        A tuple of (ip, fl_item), where ip is an instruction pointer
        to a leak from a function and fl_item is the tree item to
        this function.
    """
    assert isinstance(lib, Library)

    ip_fl_tuples = []
    for j in sorted_keys(lib.entries):
        fl = lib.entries[j]
        fl_item = LibHierarchyItem("{}".format(getCtxName(fl.fentry)), fl, parent_item)
        parent_item.appendChild(fl_item)

        assert isinstance(fl, FunctionLeak)
        for i in sorted_keys(fl.dataleaks):
            dl = fl.dataleaks[i]
            assert isinstance(dl, DataLeak)
            ip_fl_tuples.append((dl.ip, fl_item))

        for j in sorted_keys(fl.cfleaks):
            cf = fl.cfleaks[j]
            assert isinstance(cf, CFLeak)
            ip_fl_tuples.append((cf.ip, fl_item))

    return ip_fl_tuples


# Refactored from data-gui repository
def parse_leaks(lib_hierarchy):
    assert isinstance(lib_hierarchy, LibHierarchy)

    with utils.datafs.get_binfile(IP_INFO_FILE) as f:
        short_info_map = loadipinfo(f)

    for ip in sorted_keys(lib_hierarchy.entries):
        lib = lib_hierarchy.entries[ip]
        assert isinstance(lib, Library)

        lib_name = lib.libentry.name.split("/")[-1]
        lib_item = LibHierarchyItem("{}".format(lib_name), lib, lib_model.root_item)
        lib_model.root_item.appendChild(lib_item)

        bin_file_path = lib.libentry.name

        with utils.datafs.get_file(f"{bin_file_path}.asm") as f:
            asm_dump = f.read().split("\n")

        debug(0, f"[REPORT] lib_name: {lib_name}")
        debug(0, f"[REPORT] bin_path: {bin_file_path}")

        fl_entries = createLibFunctionItems(lib, lib_item)  # tuple (ip, fl_item)

        for addr, lib_tree_item in fl_entries:
            if addr not in short_info_map:
                debug(0, "Cannot find addr in short_info_map")
                debug(0, "(Could be a wrong combination of pickle and zip file?)")
                sys.exit(ErrorCode.INVALID_COMB_OF_FILES)

            leak_docs = LeakDocs(
                lib_name,
                lib_tree_item,
                addr,
                None,
                None,
            )
            if leak_docs.leak.meta is None:
                leak_docs.leak.meta = LeakMetaInfo()
            if leak_docs.leak.meta.flag == LeakFlags.DONTCARE or (
                leak_docs.leak.meta.flag != LeakFlags.LEAK
                and leak_docs.leak.status.is_generic_leak() is False
                and leak_docs.leak.status.is_specific_leak() is False
            ):
                continue

            short_info = short_info_map[addr]
            assert isinstance(short_info, IpInfoShort)

            # ASM
            if short_info.asm_line_nr < 0:
                continue
            search_str = format(utils.getLocalIp(addr), "x") + ":"
            debug(1, f"ASM search_str: {search_str}")
            search_idx = [
                idx for (idx, line) in enumerate(asm_dump) if search_str in line
            ]
            assert len(search_idx) >= 1  # search for ff0 will trigger 1ff0 as well
            search_idx = search_idx[0]
            leak_docs.asm = LeakDump(
                bin_file_path,
                search_idx,
                asm_dump[search_idx - 5 : search_idx],
                asm_dump[search_idx],
                asm_dump[search_idx + 1 : search_idx + 5],
            )

            # SRC
            src_line_nr = short_info.src_line_nr - 1
            debug(1, f"SRC src_line_nr: {src_line_nr}")
            debug(1, f"SRC src_file: {short_info.src_file}")
            leak_dump_src = None
            if short_info.src_file is None:
                debug(1, "Source file path missing: %s", short_info.src_file)
            else:
                with utils.datafs.get_file(short_info.src_file) as f:
                    src_dump = f.read().split("\n")
                debug(1, src_dump[src_line_nr])
                leak_docs.src = LeakDump(
                    short_info.src_file,
                    src_line_nr,
                    src_dump[src_line_nr - 5 : src_line_nr],
                    src_dump[src_line_nr],
                    src_dump[src_line_nr + 1 : src_line_nr + 5],
                )

            leaks_docs.append(leak_docs)
            libs_leaks_docs[lib_name].append(leak_docs)


class Report:
    lstlisting_default_style = (
        "escapechar=§,\n"
        "backgroundcolor=\color{gray!10!white},\n"
        "commentstyle=\color{green!20!black},\n"
        "basicstyle=\\ttfamily\\scriptsize,\n"
        "breakatwhitespace=false,\n"
        "breaklines=true,\n"
        "keepspaces=true,\n"
        "numbers=left,\n"
        "numbersep=5pt,\n"
        "showspaces=false,\n"
        "showstringspaces=false,\n"
        "showtabs=false,\n"
        "tabsize=2,\n"
        "}\n"
    )

    def __init__(self):
        self.doc = pylatex.Document(args.experiment)

        self.doc.packages.append(Package("hyperref", options=["hidelinks"]))
        self.doc.packages.append(Package("etoc"))

        self.doc.preamble.append(Command("title", "DATA Leakage Report"))
        self.doc.preamble.append(Command("author", "Fraunhofer AISEC"))
        self.doc.preamble.append(Command("date", pylatex.NoEscape(r"\today")))

        self.doc.append(
            NoEscape(
                "\lstdefinestyle{stylecpp}{\n"
                "language=C++,\n" + Report.lstlisting_default_style
            )
        )
        self.doc.append(
            NoEscape(
                "\lstdefinestyle{styleasm}{\n"
                "language=[x86masm]Assembler,\n" + Report.lstlisting_default_style
            )
        )

        self.doc.append(NoEscape(r"\maketitle"))
        self.doc.append(NewPage())

        self.doc.append(NoEscape(r"\setcounter{tocdepth}{1}"))
        self.doc.append(NoEscape(r"\tableofcontents"))
        self.doc.append(NoEscape(r"\setcounter{tocdepth}{2}"))
        self.doc.append(NewPage())

    def leak_overview_table(self, leaks_docs):
        lo = LeakOverview(leaks_docs)
        lo_dl = LeakOverview(leaks_docs, DataLeak)
        lo_cl = LeakOverview(leaks_docs, CFLeak)
        with self.doc.create(pylatex.Tabular("l l l l l")) as data_table:
            for lo in [lo, lo_dl, lo_cl]:
                data_table.add_row(lo.print_header())
                data_table.add_hline()
                data_table.add_row(lo.print_overview())
                data_table.add_empty_row()
        self.doc.append(NewPage())

    def status(self, leak, color):
        tooltip = getIconTooltipById(leak.meta.flag)
        string = f"Status: {TextColorExt(color, tooltip, options='HTML').dumps()}"
        self.doc.append(pylatex.utils.bold(NoEscape(string)))
        self.doc.append(NewLine())

    def criticality(self, leak):
        crit_level = f"{leak.status.max_leak_normalized():.3f}"
        if float(crit_level) == 0 and leak.meta.flag == LeakFlags.LEAK:
            crit_level = "Flagged by user"
        self.doc.append(pylatex.utils.bold(f"Criticality level: {crit_level}"))
        self.doc.append(NewLine())

    def src_dump(self, src):
        options_str = f"style=stylecpp, firstnumber={src.line}"
        self._X_dump(src, options_str)

    def asm_dump(self, asm):
        options_str = "style=styleasm"
        self._X_dump(asm, options_str)

    def _X_dump(self, x, options_str):
        with self.doc.create(
            LstListing(options=[f"{options_str}, caption={x.filename}"])
        ):
            self.doc.append("\n".join(x.print_tex()))

    def comment(self, leak):
        self.doc.append(pylatex.utils.bold("Comment:"))
        self.doc.append(NewLine())
        comment = str(leak.meta.comment)
        comment = comment if len(comment) else "[empty]"
        self.doc.append(comment)
        self.doc.append(NewLine())

    def statistics(self, leak):
        ml = leak.status.max_leak()
        if ml is None:
            return
        self.doc.append(NewLine())
        self.doc.append(pylatex.utils.bold("Generic Test Result:"))
        self.doc.append(NewLine())
        ml_type = f"H_{ml.nstype}" if isinstance(ml, NSLeak) else f"M_{ml.sptype}"
        with self.doc.create(pylatex.Tabular("l l l l l")) as data_table:
            data_table.add_row(
                ["Source", "Kuiper", "Significance", "Confidence", "Key"]
            )
            data_table.add_hline()
            data_table.add_row(
                [
                    ml_type,
                    f"{ml.teststat:.3f}",
                    f"{ml.limit:.3f}",
                    f"{ml.confidence}",
                    str(ml.key),
                ]
            )
        self.doc.append(NewLine())

    def generate_leak_page(self, leak_docs):
        color = hex(getIconColorById(leak_docs.leak.meta.flag))[2:]

        subsection_title = pylatex.escape_latex(
            f"{leak_docs.leak.name} in {leak_docs.fn_name}"
        )
        subsection = TextColorExt(color, subsection_title, options="HTML")
        with self.doc.create(Subsection(NoEscape(subsection.dumps()))):
            self.status(leak_docs.leak, color)
            self.criticality(leak_docs.leak)
            if leak_docs.src is not None:
                self.src_dump(leak_docs.src)
            self.asm_dump(leak_docs.asm)
            self.comment(leak_docs.leak)
            self.statistics(leak_docs.leak)
            self.doc.append(NewPage())

    def generate(self, leaks_docs, libs_leaks_docs):
        self.leak_overview_table(leaks_docs)

        for lib_name, leaks_docs in libs_leaks_docs.items():
            with self.doc.create(Section(f"Binary: {lib_name}")):
                self.leak_overview_table(leaks_docs)

                self.doc.append(NoEscape(r"\localtableofcontents"))
                self.doc.append(NewPage())

                for leak_docs in sorted(leaks_docs):
                    self.generate_leak_page(leak_docs)

        self.doc.generate_pdf(clean_tex=False)
        self.doc.generate_tex()


if __name__ == "__main__":
    if args.pickle is None or args.zip is None:
        experiment_dir = "/".join(args.experiment.split("/")[:-1])
        results = list()
        for file in glob.glob(f"{experiment_dir}/{'*'.join(PICKLE)}"):
            results.append(file)
        args.pickle = sorted(results)[-1]
        args.zip = f"{experiment_dir}/{ZIP}"

        debug(0, f"[REPORT] Automatically selected {args.pickle}")
        debug(0, f"[REPORT] Automatically selected {args.zip}")

    try:
        call_hierarchy = loadpickle(args.pickle)
        if not call_hierarchy:
            raise FileNotFoundError()
    except FileNotFoundError:
        debug(0, "Please enter a valid pickle file path (mandatory)")
        sys.exit(ErrorCode.INVALID_PICKLE)
    except Exception as e:
        debug(0, f"Unable to load pickle file at {args.pickle}")
        debug(1, "Exception: " + str(e))
        sys.exit(ErrorCode.CANNOT_LOAD_PICKLE)

    try:
        utils.setupSymbolInfo(args.zip)
    except FileNotFoundError:
        debug(0, "Please enter a valid zip file path (mandatory)")
        sys.exit(ErrorCode.INVALID_ZIP)
    except Exception:
        debug(0, f"Unable to load zip file at {args.zip}")
        sys.exit(ErrorCode.CANNOT_LOAD_ZIP)

    if call_hierarchy is None:
        debug(0, "Error opening pickle/zip file")
        sys.exit(ErrorCode.CANNOT_LOAD_PICKLE)

    lib_hierarchy = call_hierarchy.flatten()
    lib_model = LibHierarchyModel()
    lib_model.setRootItem(lib_hierarchy)

    leaks_docs = list()
    libs_leaks_docs = defaultdict(list)

    parse_leaks(lib_hierarchy)

    report = Report()
    report.generate(leaks_docs, libs_leaks_docs)
