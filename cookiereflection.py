import sys

from burp import IBurpExtender, IScannerCheck, IScanIssue
import jarray


class BurpExtender(IBurpExtender, IScannerCheck):

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		print("Loaded Reflected Cookie Scanner")
		print("Github: https://github.com/alexvec/BurpSuite_CookieReflection")
		callbacks.setExtensionName("Cookie Reflection Checker")
		callbacks.registerScannerCheck(self)

		return

	def doPassiveScan(self, baseRequestResponse):

		# Get headers from the request
		headers = self._helpers.analyzeRequest(baseRequestResponse).getHeaders()
		cookies = []

		# Extracting cookies from headers
		for header in headers:
			if header.startswith("Cookie:"):
				# Split the cookie header to get individual cookies
				for cookie_pair in header.split(":")[1].split(";"):
					cookie_name, cookie_value = cookie_pair.strip().split("=", 1)
					cookies.append((self._helpers.urlDecode(cookie_name), self._helpers.urlDecode(cookie_value)))

		if cookies:
			reflected_cookies = []
			request_highlights = []
			response_highlights = []

			request = self._helpers.bytesToString(baseRequestResponse.getRequest())
			response = self._helpers.bytesToString(baseRequestResponse.getResponse())
			response_body = self._helpers.urlDecode(self._helpers.bytesToString(baseRequestResponse.getResponse()).split('\r\n\r\n', 1)[1])

			for (cookie_name, cookie_value) in cookies:
				is_name_reflected = cookie_name in response_body
				is_value_reflected = cookie_value in response_body

				if cookie_name in request:
					request_start = request.index(cookie_name)
					request_highlights.append([request_start, request_start + len(cookie_name)])

				if cookie_value in request:
					request_start = request.index(cookie_value)
					request_highlights.append([request_start, request_start + len(cookie_value)])

				if is_name_reflected:
					response_start = response.index(cookie_name)
					response_highlights.append([response_start, response_start + len(cookie_name)])

				if is_value_reflected:
					response_start = response.index(cookie_value)
					response_highlights.append([response_start, response_start + len(cookie_value)])

				if is_name_reflected or is_value_reflected:
					reflected_cookies.append((cookie_name if is_name_reflected else None,
											  cookie_value if is_value_reflected else None))

			# If there are any reflected cookie details, raise a single issue
			if reflected_cookies:
				return [ReflectedCookieIssue(baseRequestResponse, reflected_cookies, pylistlist_to_java_array(request_highlights), pylistlist_to_java_array(response_highlights), self._callbacks, self._helpers)]

		return []

	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if existingIssue.getIssueName() == newIssue.getIssueName() and existingIssue.getIssueDetail() == newIssue.getIssueDetail():
			return -1
		return 0

class ReflectedCookieIssue(IScanIssue):

	def __init__(self, requestResponse, reflected_cookies, request_highlights, response_highlights, callbacks, helpers):
		self._callbacks = callbacks
		self._helpers = helpers
		self._requestResponse = requestResponse
		self._reflected_cookies = reflected_cookies
		self._request_highlights = request_highlights
		self._response_highlights = response_highlights

	def getUrl(self):
		return self._helpers.analyzeRequest(self._requestResponse).getUrl()

	def getIssueName(self):
		return "Cookie Reflection"

	def getIssueType(self):
		return 0x08000000  # Custom issue type

	def getSeverity(self):
		return "Information"

	def getConfidence(self):
		return "Certain"

	def getIssueBackground(self):
		return "It has been observed that there is reflection of cookie details in the response body. This might be benign but in some cases could be indicative of potential issues."

	def getIssueDetail(self):
		details = "The following cookie details were reflected in the response body:<br><br>"

		for cookie_name, cookie_value in self._reflected_cookies:
			details += "<b>Cookie Name:</b> " + (cookie_name if cookie_name else "Not Reflected")
			details += "<br><b>Cookie Value:</b> " + (cookie_value if cookie_value else "Not Reflected")
			details += "<br>"

		return details

	def getRemediationDetail(self):
		return None

	def getRemediationBackground(self):
		return None

	def getHttpMessages(self):
		return [self._callbacks.applyMarkers(self._requestResponse, self._request_highlights, self._response_highlights)]

	def getHttpService(self):
		return self._requestResponse.getHttpService()


def pylistlist_to_java_array(pylistlist):
	return [jarray.array(item, 'i') for item in pylistlist]
