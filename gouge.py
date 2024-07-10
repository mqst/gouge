from burp import IBurpExtender, IScannerCheck, IScanIssue
import re



class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Gouge")
        callbacks.registerScannerCheck(self)
        callbacks.issueAlert("Gouge registered for gouging!")
        print("Gouge extension loaded")
    # Improved URL Regex (consider further adjustments based on your needs)
    url_regex = r"(https?://[^\s\"']+)"  
    def doPassiveScan(self, baseRequestResponse):
        issues = []
        headers, body = self.get_http_response_headers_and_body(baseRequestResponse)
        urls = self.find_urls(body)
        if urls:
            print("Gouge found URLs in response:")
            for url in urls:
                print(url)
                self.check_and_process_js_urls(url)  # Call to process potential JS URLs

    def get_http_response_headers_and_body(self, content):
        response = content.getResponse()
        response_data = self._helpers.analyzeResponse(response)
        headers = list(response_data.getHeaders())
        body = response[response_data.getBodyOffset():].tostring()
        return headers, body

    def find_urls(self, body):
        urls = re.findall(self.url_regex, body)
        return urls

    def check_and_process_js_urls(self, url):
        if url.endswith(".js"):
            js_response = self.make_http_request(url)
            if js_response:
                js_headers, js_body = self.get_http_response_headers_and_body(js_response)
                js_urls = self.find_urls(js_body)
                if js_urls:
                    print("Found URLs in JS file:", url)
                    # Process or store the found JS URLs (implement your logic here)

    def make_http_request(self, url):
        http_request = self._helpers.buildHttpRequest(url)
        try:
            return self._callbacks.makeHttpRequest(http_request)
        except Exception as e:
            return None