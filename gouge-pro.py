from burp import IBurpExtender, IScannerCheck, IContextMenuFactory
from java.util import List, ArrayList
from javax.swing import JMenuItem
import re
from java.net import URL
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
from java.lang import Runnable, Thread

class BurpExtender(IBurpExtender, IScannerCheck, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Gouge")
        callbacks.registerScannerCheck(self)
        callbacks.issueAlert("Gouge extension registered successfully!")
        print("Gouge extension loaded and ready to gouge for URLs!")
        callbacks.registerContextMenuFactory(self)

    # Enhanced regex for URLs & JS files.
    url_regex = r"https?://[^\s\"']+"
    js_file_regex = r"https?://[^\s\"']+\.(js|jsx)(\?.*)?"

    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        menu_item = JMenuItem("Copy all URLs (including from JS files)", actionPerformed=lambda x: self.copy_urls(invocation))
        menu_list.add(menu_item)
        return menu_list

    def copy_urls(self, invocation):
        thread = Thread(CopyUrlsRunnable(self, invocation))
        thread.start()

    def find_urls(self, body):
        urls = re.findall(self.url_regex, body)
        return urls

    def make_http_request(self, url):
        try:
            java_url = URL(url)
            host = java_url.getHost()
            port = java_url.getPort() if java_url.getPort() != -1 else (443 if java_url.getProtocol() == "https" else 80)
            protocol = java_url.getProtocol()
            path = java_url.getPath()

            service = self._helpers.buildHttpService(host, port, protocol)
            request = self._helpers.buildHttpRequest(java_url)
            response = self._callbacks.makeHttpRequest(service, request)
            if response:
                return response.getResponse()
            else:
                print("[-] No response received for URL", url)
                return None
        except Exception as e:
            print("[-] Error making HTTP request for URL", url, ":", e)
            return None

    def copy_to_clipboard(self, text):
        try:
            string_selection = StringSelection(text)
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(string_selection, None)
            print("[+] URLs copied to clipboard successfully.")
        except Exception as e:
            print("[-] Error copying to clipboard:", e)

    def doPassiveScan(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()
        if response:
            response_info = self._helpers.analyzeResponse(response)
            body = response[response_info.getBodyOffset():].tostring()
            urls = self.find_urls(body)
            all_urls = set()
            for url in urls:
                all_urls.add(url)
                if re.match(self.js_file_regex, url):
                    js_response = self.make_http_request(url)
                    if js_response:
                        js_response_info = self._helpers.analyzeResponse(js_response)
                        js_body = js_response[js_response_info.getBodyOffset():].tostring()
                        js_urls = self.find_urls(js_body)
                        all_urls.update(js_urls)

            all_urls_string = "\n".join(all_urls)
            print("[+] URLs found during passive scan:")
            print(all_urls_string)

        return None

class CopyUrlsRunnable(Runnable):
    def __init__(self, extender, invocation):
        self._extender = extender
        self._invocation = invocation

    def run(self):
        http_traffic = self._invocation.getSelectedMessages()
        all_urls = set()

        for message in http_traffic:
            response = message.getResponse()
            if response:
                response_info = self._extender._helpers.analyzeResponse(response)
                body = response[response_info.getBodyOffset():].tostring()
                urls = self._extender.find_urls(body)
                for url in urls:
                    all_urls.add(url)
                    if re.match(self._extender.js_file_regex, url):
                        js_response = self._extender.make_http_request(url)
                        if js_response:
                            js_response_info = self._extender._helpers.analyzeResponse(js_response)
                            js_body = js_response[js_response_info.getBodyOffset():].tostring()
                            js_urls = self._extender.find_urls(js_body)
                            all_urls.update(js_urls)

        all_urls_string = "\n".join(all_urls)
        self._extender.copy_to_clipboard(all_urls_string)
        print("[+] URLs copied to clipboard.")
