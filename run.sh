#!/bin/bash
sudo apt update && apt install -y git python3 python3-pip libopenscap8 unzip
git clone https://github.com/SamoylikV/FstekOvalCheck.git
pip install -r FstekOvalCheck/requirements.txt
cd FstekOvalCheck
python3 main.py
oscap oval eval --results results.xml --report report.html CVE.FSTEK.xml
python3 reformat_html.py
