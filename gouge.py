from burp import IBurpExtender, IScannerCheck, IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):   
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Gouge")
        print("Gouge extension loaded")

    def doPassiveScan(self, baseRequestResponse):
        pass
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

