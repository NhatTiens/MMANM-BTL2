"""Optional UI smoke with Playwright; uses only fixture server and local browser."""
import argparse, os, subprocess, sys, time, urllib.request
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]

def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',type=Path,required=True); p.add_argument('--chromium'); a=p.parse_args()
    from playwright.sync_api import sync_playwright, expect
    a.output.mkdir(parents=True,exist_ok=False)
    # Reserve fixture-only port 8501; refuse to accidentally test a running live lab.
    import socket
    with socket.socket() as sock: sock.bind(('127.0.0.1',8501))
    proc=subprocess.Popen([sys.executable,str(ROOT/'tests/member4_dashboard/fixture_server.py')],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        for _ in range(40):
            try:
                with urllib.request.urlopen('http://127.0.0.1:8501/healthz',timeout=1): break
            except OSError: time.sleep(.1)
        with sync_playwright() as pw:
            browser=pw.chromium.launch(executable_path=a.chromium,headless=True,args=['--no-sandbox'] if os.name!='nt' and os.getuid()==0 else [])
            page=browser.new_page(viewport={'width':1440,'height':1000},accept_downloads=True)
            errors=[]; page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto('http://127.0.0.1:8501/'); expect(page.locator('#mode')).to_have_text('DỮ LIỆU GIẢ LẬP'); expect(page.locator('#count')).to_have_text('3'); expect(page.locator('#alerts tr')).to_have_count(3)
            page.locator('#action').select_option('blocked'); expect(page.locator('#alerts tr')).to_have_count(1); expect(page.locator('#alerts')).to_contain_text('1000007')
            page.locator('#action').select_option(''); page.locator('#query').fill('1000002'); expect(page.locator('#alerts tr')).to_have_count(1); expect(page.locator('#alerts')).to_contain_text('1000002')
            page.locator('#query').fill(''); page.locator('#severity').select_option('1'); expect(page.locator('#alerts')).to_contain_text('1000007'); page.locator('#severity').select_option('')
            with page.expect_download() as dl: page.get_by_text('Xuất CSV (cửa sổ mới)').click()
            dl.value.save_as(a.output/'fixture-alerts.csv'); assert 'fixture' in (a.output/'fixture-alerts.csv').read_text(encoding='utf-8-sig')
            page.locator('#refresh').click(); expect(page.locator('#count')).to_have_text('3'); page.screenshot(path=a.output/'dashboard-desktop-fixture.png',full_page=True)
            page.set_viewport_size({'width':390,'height':844}); page.screenshot(path=a.output/'dashboard-mobile-fixture.png',full_page=True)
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'); assert not errors,errors
            browser.close()
        print('PASS browser: fixture banner, counts, action/search/severity filters, CSV, refresh, desktop/mobile, no JS errors')
    finally: proc.terminate(); proc.wait(timeout=5)
if __name__=='__main__': main()
