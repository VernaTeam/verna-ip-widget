"""Console-less entry point for the Verna IP Widget.

Double-clicking a .pyw file runs it under pythonw.exe, so no console window
appears. This is a three-line shim on purpose: it used to be a byte-for-byte
copy of ip_widget.py, which meant every edit had to be made twice and the
two files silently drifted apart the first time one was forgotten.
"""

import sys

from ip_widget import IPWidget, acquire_single_instance_lock

if __name__ == "__main__":
    if not acquire_single_instance_lock():
        sys.exit(0)  # another instance is already running
    IPWidget().run()
