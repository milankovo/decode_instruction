#!/bin/bash
python3 ./extract_constants.py
cmake -B build -DEA64=YES -S src
cmake --build build --config MinSizeRel -j 8
