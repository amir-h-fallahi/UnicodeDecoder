from burp import IBurpExtender, IHttpListener
import codecs

class BurpExtender(IBurpExtender, IHttpListener):

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Unicode Decoder")
		callbacks.registerHttpListener(self)

		callbacks.printOutput("::Unicode Decoder::")
		callbacks.printOutput("Author: Amir Hossein Fallahi")
		callbacks.printOutput("Version: 1.0")
		callbacks.printOutput("Description: This is a Burp Suite extension that automatically decodes unicode escape sequences. It supports Persian, Chinese, Russian and other languages probably. Also works on Proxy, Repeater and Intruder Tools.")
		callbacks.printOutput("GitHub: https://github.com/amir-h-fallahi/UnicodeDecoder")

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		toolName = self._callbacks.getToolName(toolFlag)
		if toolName == "Repeater" or toolName == "Proxy" or toolName == "Intruder":
			if not messageIsRequest:
				is_response_json = False

				response = messageInfo.getResponse()
				analyzedResponse = self._helpers.analyzeResponse(response)
				response_headers = analyzedResponse.getHeaders()

				for header in response_headers:
					if header.lower().startswith("content-type: application/json"):
						is_response_json = True

				if is_response_json:
					bodyBytes = response[analyzedResponse.getBodyOffset():]
					bodyStr = self._helpers.bytesToString(bodyBytes)
					decodeUnicodes = codecs.decode(bodyStr, "unicode_escape").encode("utf-8")

					# codecs.decode(), decodes \r\n caracter as carriage return and line feed, we should replace this pattern
					modifiedBody = decodeUnicodes.replace("\r\n", "\\r\\n")

					finalModifiedBody = self._helpers.stringToBytes(modifiedBody)
					modifiedResponse = self._helpers.buildHttpMessage(response_headers, finalModifiedBody)
					messageInfo.setResponse(modifiedResponse)

