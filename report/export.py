import argparse
import glob
import os
import pathlib
import shlex
import shutil
import subprocess


parser = argparse.ArgumentParser(description="DATA Export")
parser.add_argument("name", help="Name of the zipped export")
parser.add_argument("results", nargs="+", help="Path to the 'results directory'")
args = parser.parse_args()

if r"/" in args.name:
    print(f"[EXPORT] ERROR: '/' in not allowed in args.name: {args.name}")
    exit(1)

PICKLE = ["result_phase", ".pickle"]
XML = ["result_phase", ".xml"]
ZIP = "framework.zip"

cwd = os.getcwd()
export_dirs = list()
for args_result in args.results:
    print(f"[EXPORT] Export started for {args_result}")
    for root, dirs, files in os.walk(args_result):
        if ZIP not in files:
            continue
        print(f"[EXPORT] Results found in {root}")
        # Search for the phase pickle with the highest index
        results = list()
        for file in glob.glob(f"{root}/{'*'.join(PICKLE)}"):
            results.append(file)
        result = sorted(results)[-1]
        # Copy files into the export directory
        export_dir = root.replace(args_result, "").replace("/", "_").lstrip("_")
        export_dirs.append(export_dir)
        pathlib.Path(f"{root}/{export_dir}", exist_ok=True)
        for xml in glob.glob(f"{root}/{'*'.join(XML)}"):
            shutil.copy(xml, f"{export_dir}/.")
        shutil.copy(f"{result}", f"{export_dir}/.")
        shutil.copy(f"{root}/{ZIP}", f"{export_dir}/.")
        # Create report
        report_cmd = f"python report.py {export_dir} {result} {root}/{ZIP}"
        subprocess.run(report_cmd, shell=True, check=True)
        shutil.copy(f"{export_dir}.pdf", f"{export_dir}/.")
        # Cleanup directory
        subprocess.run(f"rm {export_dir}.*", shell=True, check=True)

# Zip export directories
subprocess.run(
    f"zip -r {args.name}.zip {' '.join(export_dirs)}", shell=True, check=True
)
