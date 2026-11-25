"""Run a clearly labeled offline fixture UI, bound to loopback only."""
import os, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
fixtures=Path(__file__).with_name('fixtures')
os.environ.update(IDS_LOG_PATH=str(fixtures/'eve.json'),FW_LOG_PATH=str(fixtures/'counters.json'),DASHBOARD_MODE='fixture')
from srcs.member4_dashboard.app import ThreadingHTTPServer, Handler
if __name__=='__main__':
    print('FIXTURE only: http://127.0.0.1:8501',flush=True)
    ThreadingHTTPServer(('127.0.0.1',8501),Handler).serve_forever()
