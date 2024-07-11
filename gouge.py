from burp import IBurpExtender, IScannerCheck
import re
from java.net import URL

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Gouge")
        callbacks.registerScannerCheck(self)
        callbacks.issueAlert("Gouge extension registered successfully!")
        print("Gouge extension loaded and ready to gouge for JS URLs!")

    # Regex for URLs & JS files.
    url_regex = r"https?://[^\s\"']+"
    js_file_regex = r"https?://[^\s\"']+\.(js|jsx)"

    def doPassiveScan(self, baseRequestResponse):
        response = baseRequestResponse.getResponse()
        response_info = self._helpers.analyzeResponse(response)
        body = response[response_info.getBodyOffset():].tostring()

        urls = self.find_urls(body)
        if urls:
            print("\n[+] Found URLs in response:")
            for url in urls:
                print("  -", url)
                self.check_and_process_js_urls(url)

    def find_urls(self, body):
        urls = re.findall(self.url_regex, body)
        return urls

    def check_and_process_js_urls(self, url):
        if re.match(self.js_file_regex, url):
            print("    [+] JS URL found:", url)
            js_response = self.make_http_request(url)
            if js_response:
                js_response_info = self._helpers.analyzeResponse(js_response)
                js_body = js_response[js_response_info.getBodyOffset():].tostring()
                js_urls = self.find_urls(js_body)
                if js_urls:
                    print("      [+] Found URLs in JS file:", url)
                    for found_url in js_urls:
                        print("        -", found_url)

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
            return response.getResponse()
        except Exception as e:
            print("    [-] Error making HTTP request for URL", url, ":", e)
            return None
