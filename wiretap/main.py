#!/usr/bin/env python3
"""Entry point for wiretap - launches the GUI application."""

import sys
import os

# Add the parent directory to the path so we can import wiretap package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wiretap.gui.main_window import main

if __name__ == "__main__":
    main()