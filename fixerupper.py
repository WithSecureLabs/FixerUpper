"""
@author: Oliver Simonnet (@AppSecOllie)

Released as open source by F-Secure Labs (c) 2021
under BSD 3-Clause License. See LICENSE for more.
"""

from burp import IBurpExtender
from burp import IHttpListener
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory 
from burp import ITab 

from javax.swing import JScrollPane
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JTextArea
from javax.swing import JLabel
from javax.swing import SwingConstants
from javax.swing import GroupLayout

from javax.swing.border import EmptyBorder
from java.awt import Dimension, Font, Color

import csv
import re

EXT_FILE_PATH = None
EXT_FILE_NAME = None
EXT_NAME = "Fixer Upper"
EXT_FIX_DICT = "FIX4.4.csv"
FIX_SOH = "\x01"

FIX_MSG_BODY_REGEX = ""
FIX_MSG_HEADERS_REGEX = []

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IHttpListener, ITab):

	def registerExtenderCallbacks(self, callbacks):
		self.callbacks = callbacks
		self.helpers = callbacks.getHelpers()

		global EXT_FILE_NAME, EXT_FILE_PATH
		EXT_FILE_NAME = callbacks.getExtensionFilename().split("/")[-1]
		EXT_FILE_PATH = callbacks.getExtensionFilename().replace(EXT_FILE_NAME, "")

		self.raw_content = None
		self.req_obj = None
		self.req_headers = None
		self.req_body = None

		self.fixer = Fixer(FIX_SOH)

		global FIX_MSG_BODY_REGEX, FIX_MSG_HEADERS_REGEX
		FIX_MSG_BODY_REGEX = self.load_config("FIX_MSG_BODY_REGEX")
		FIX_MSG_HEADERS_REGEX = self.load_config("FIX_MSG_HEADERS_REGEX")

		callbacks.setExtensionName(EXT_NAME)
		callbacks.addSuiteTab(self)
		callbacks.registerHttpListener(self)
		callbacks.registerMessageEditorTabFactory(self)

	def createNewInstance(self, controller, editable):
		return Display_data(self, controller, editable)

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		if messageIsRequest:

			self.raw_content = messageInfo.getRequest()

			if messageIsRequest:
				self.req_obj = self.helpers.analyzeRequest(self.raw_content)
			else:
				self.req_obj = self.helpers.analyzeResponse(self.raw_content)

			if self.req_obj != None:
				self.req_headers = self.req_obj.getHeaders()
				self.req_body = self.raw_content[(self.req_obj.getBodyOffset()):].tostring()

				if self.fixer.validate_message(self.req_headers, self.req_body):
					message = self.req_body
					message = self.fixer.update_field(message,  "9", self.fixer.calc_length(message))
					message = self.fixer.update_field(message, "10", self.fixer.calc_chksum(message))
					print(message.replace(FIX_SOH, "|"))
					print("---------------------")

					new_req = self.helpers.buildHttpMessage(self.req_obj.getHeaders(), message)
					messageInfo.setRequest(new_req)

	def getTabCaption(self):
		return EXT_NAME

	def save_criteria(self, event):
		global FIX_MSG_HEADERS_REGEX, FIX_MSG_BODY_REGEX
		FIX_MSG_HEADERS_REGEX = self.txtHeaderFlags.getText().split("\n")
		FIX_MSG_BODY_REGEX = self.txtBodyFlags.getText().rstrip()
		self.callbacks.saveExtensionSetting("FIX_MSG_BODY_REGEX", FIX_MSG_BODY_REGEX);
		self.callbacks.saveExtensionSetting("FIX_MSG_HEADERS_REGEX", '\n'.join(FIX_MSG_HEADERS_REGEX));
		print("--- CONFIG SAVED ---")

	def getUiComponent(self):
		panel = JPanel()
		layout = GroupLayout(panel)
		panel.setLayout(layout)
		panel.setBorder(EmptyBorder(10, 10, 10, 10));
		
		lblPanelHeading = JLabel(EXT_NAME + " Options", SwingConstants.LEFT)
		lblPanelHeading.setFont(Font("Tahoma", Font.BOLD, 14))
		lblPanelHeading.setForeground(Color(235,136,0))

		globalwidth = 500

		self.lblHeadFlags = JLabel("Required Header Patterns:", SwingConstants.LEFT)
		self.txtHeaderFlags = JTextArea(2, 10)
		self.txtHeaderFlags.setMaximumSize(Dimension(10, self.txtHeaderFlags.getPreferredSize().height))
		self.txtHeaderFlags.setMinimumSize(Dimension(10, self.txtHeaderFlags.getPreferredSize().height))
		self.pnlHeaderFlags = JScrollPane(self.txtHeaderFlags)
		self.pnlHeaderFlags.setMaximumSize(Dimension(globalwidth, self.txtHeaderFlags.getPreferredSize().height * 2))
		self.pnlHeaderFlags.setMinimumSize(Dimension(globalwidth, self.txtHeaderFlags.getPreferredSize().height * 2))
		self.txtHeaderFlags.setText('\n'.join(FIX_MSG_HEADERS_REGEX))

		self.lblBodyFlags = JLabel("Message Body Pattern:", SwingConstants.LEFT)
		self.txtBodyFlags = JTextArea(2, 10)
		self.txtBodyFlags.setMaximumSize(Dimension(10, self.txtBodyFlags.getPreferredSize().height))
		self.txtBodyFlags.setMinimumSize(Dimension(10, self.txtBodyFlags.getPreferredSize().height))
		self.pnlBodyFlags = JScrollPane(self.txtBodyFlags)
		self.pnlBodyFlags.setMaximumSize(Dimension(globalwidth, self.txtBodyFlags.getPreferredSize().height * 2))
		self.pnlBodyFlags.setMinimumSize(Dimension(globalwidth, self.txtBodyFlags.getPreferredSize().height * 2))
		self.txtBodyFlags.setText(FIX_MSG_BODY_REGEX)
		
		self.btnSubmit = JButton("Save", actionPerformed=self.save_criteria)
		self.btnSubmit.setMaximumSize(Dimension(globalwidth, self.btnSubmit.getPreferredSize().height))
		self.btnSubmit.setMinimumSize(Dimension(globalwidth, self.btnSubmit.getPreferredSize().height))

		lblPanelContext = JLabel(
			"These values define the criteria for whether a request should be processed as a FIX message or not",
			SwingConstants.LEFT
		)
		lblPanelContext.setFont(Font("Tahoma", Font.ITALIC, 12))

		# ----------------------------------

		gl = GroupLayout.Alignment.LEADING

		leftToRight = layout.createSequentialGroup()
		col1 = layout.createParallelGroup(gl)
		col1.addGap(10,10,10)
		col1.addComponent(lblPanelHeading)
		col1.addGap(10,10,10)
		col1.addComponent(lblPanelContext)
		col1.addGap(10,10,10)
		col1.addComponent(self.lblHeadFlags)
		col1.addComponent(self.pnlHeaderFlags)
		col1.addGap(10,10,10)
		col1.addComponent(self.lblBodyFlags)
		col1.addComponent(self.pnlBodyFlags)
		col1.addGap(10,10,10)
		col1.addComponent(self.btnSubmit)
		
		leftToRight.addGroup(col1)
		leftToRight.addContainerGap(500, globalwidth)

		# ----------------------------------

		topToBottom = layout.createSequentialGroup()
		topToBottom.addGroup(layout.createParallelGroup(gl).addGap(10,10,10))
		topToBottom.addGroup(layout.createParallelGroup(gl).addComponent(lblPanelHeading))
		topToBottom.addGroup(layout.createParallelGroup(gl).addGap(10,10,10))
		topToBottom.addGroup(layout.createParallelGroup(gl).addComponent(lblPanelContext))
		topToBottom.addGroup(layout.createParallelGroup(gl).addGap(10,10,10))
		topToBottom.addGroup(layout.createParallelGroup(gl).addComponent(self.lblHeadFlags))
		topToBottom.addGroup(layout.createParallelGroup(gl).addComponent(self.pnlHeaderFlags))
		topToBottom.addGroup(layout.createParallelGroup(gl).addGap(10,10,10))
		topToBottom.addGroup(layout.createParallelGroup(gl).addComponent(self.lblBodyFlags))
		topToBottom.addGroup(layout.createParallelGroup(gl).addComponent(self.pnlBodyFlags))
		topToBottom.addGroup(layout.createParallelGroup(gl).addGap(10,10,10))
		topToBottom.addGroup(layout.createParallelGroup(gl).addComponent(self.btnSubmit))

		layout.setHorizontalGroup(leftToRight)
		layout.setVerticalGroup(topToBottom)

		return panel

	def load_config(self, config_name):
		config_value = self.callbacks.loadExtensionSetting(config_name)
		if config_value == None:
			if config_name == "FIX_MSG_BODY_REGEX":
				config_value = r"^8=FIX\.4\..*10\=[0-9]{3}"

			elif config_name == "FIX_MSG_HEADERS_REGEX":
				config_value = ["^X-Mitm_Relay-To:.*", "^X-Mitm_Relay-From:.*"]

		if config_name == "FIX_MSG_HEADERS_REGEX" and "\n" in config_value:
			config_value = config_value.split("\n")

		return config_value

class Display_data(IMessageEditorTab):

	def __init__(self, extender, controller, editable):
		self.extender = extender
		self.controller = controller
		self.editable = editable

		self.editor = extender.callbacks.createTextEditor()
		self.helpers = extender.helpers

		self.raw_content = None
		self.req_obj = None
		self.req_headers = None
		self.req_body = None

		self.fixer = Fixer(FIX_SOH)

	def getUiComponent(self):
		return self.editor.getComponent()

	def getTabCaption(self):
		return EXT_NAME

	def getSelectedData(self):        
		return self.editor.getSelectedText()

	def isModified(self):
		return self.editor.isTextModified()

	def isEnabled(self, content, isRequest):
		self.raw_content = content
		if isRequest:
			self.req_obj = self.helpers.analyzeRequest(self.raw_content)
		else:
			self.req_obj = self.helpers.analyzeResponse(self.raw_content)

		if self.req_obj != None:
			self.req_headers = self.req_obj.getHeaders()
			self.req_body = self.raw_content[(self.req_obj.getBodyOffset()):].tostring()

			if self.fixer.validate_message(self.req_headers, self.req_body):
				return True

		return False

	def setMessage(self, content, isRequest):
		if content is None:
			self.editor.setText(None)
			self.editor.setEditable(False)
		else:
			self.editor.setText(self.fixer.msg_expand(self.req_body))

	def getMessage(self):
		if(self.editor.isTextModified()):
			return self.helpers.buildHttpMessage(self.req_headers, 
				self.fixer.msg_compress(self.editor.getText())
			)
		else:
			return self.raw_content

class Fixer():

	def __init__(self, SOH):
		self.SOH = SOH
		self.FIX_DICT = None

		try:
			with open(EXT_FILE_PATH + EXT_FIX_DICT, mode="r") as infile:
				self.FIX_DICT = { 
					rows[0]:rows[1] for rows in csv.reader(infile)
				}
		except:
			print("ERROR: " + EXT_FIX_DICT + " Not Found!")
			self.FIX_DICT = {"MISSING":"MISSING"}

	def update_field(self, message, flag, new_value):
		msg_fields = message.split(self.SOH)
		for i, field in enumerate(msg_fields):
			if field.startswith(flag + "="):
				msg_fields[i] = flag + "=" + str(new_value)
				break

		new_message = self.SOH.join(msg_fields)

		return new_message

	def calc_chksum(self, message):
		checksum = 0
		for c in message[:message.index("10=")]:
			checksum += ord(c)
		checksum = str(checksum % 256).zfill(3)

		return checksum

	def calc_length(self, message):
		msg_fields = message.split(self.SOH)
		length = len(self.SOH.join(msg_fields[2:-2]) + self.SOH)

		return length

	def validate_message(self, headers, body):
		return (
			all(
				any(
					re.match(re.compile(exp), h) 
					for h in headers
				) 
				for exp in FIX_MSG_HEADERS_REGEX
			)
			and re.match(FIX_MSG_BODY_REGEX, body)
		)

	def get_field_name(self, field_num):
		try:
			return self.FIX_DICT[field_num]
		except KeyError as e:
			return "UNKNOWN"

	def msg_expand(self, message):
		fields = message.split(self.SOH)
		output = ""
		for field in fields: 
			if field != "":
				field_pair = field.split("=")
				field_name = self.get_field_name(field_pair[0])
				output += field_pair[0]+"("+field_name+")=" + field_pair[1] + "\n"

		return output

	def msg_compress(self, message):
		message = re.sub(r'\(.*\)\=', "=", message)
		message = message.replace("\n", self.SOH)
		message = message[:message.index("|10=")+8]

		return message