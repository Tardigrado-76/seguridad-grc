import contextlib
import os
import sys
import tkinter as tk
from tkinter import filedialog


def main() -> None:
    root = tk.Tk()
    root.attributes("-topmost", True)
    root.withdraw()
    initial_dir = None
    if len(sys.argv) > 1:
        candidate = sys.argv[1].strip(' \'"\u202A\u202B\u202C\u202D\u202E')
        if os.path.isdir(candidate):
            initial_dir = candidate
    try:
        folder = filedialog.askdirectory(parent=root, initialdir=initial_dir, title="Seleccionar Carpeta")
    except Exception:  # noqa: BLE001
        folder = None
    finally:
        with contextlib.suppress(Exception):
            root.destroy()
    if folder:
        print(folder)


if __name__ == "__main__":
    main()
