# LightIDS_Pro (User-Ready)

Quickstart:
1. Open Anaconda/git-bash Prompt (Windows) as Administrator.
2. (Optional) Create env:
   conda create -n lightids python=3.10 -y
   conda activate lightids
3. Install deps:
   pip install -r requirements.txt
4. List interfaces:
   python -m src.main --list-ifaces
5. Run (replace iface name as needed):
   python -m src.main --iface "Ethernet 8" --stats-every 5
