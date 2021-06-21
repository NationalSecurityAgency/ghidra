/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.program.model.lang;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;

import javax.xml.parsers.SAXParser;

import org.xml.sax.*;
import org.xml.sax.helpers.DefaultHandler;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.pcode.*;
import ghidra.util.xml.SpecXmlUtils;

public class InjectContext {
	private class Handler extends DefaultHandler {
		private AddressFactory addrFactory;
		private Address curaddr;
		private int state;

		Handler(AddressFactory adFact) {
			super();
			state = 0;
			addrFactory = adFact;
		}

		@Override
		public void startElement(String uri, String localName, String rawName, Attributes attr)
				throws SAXException {
			if (rawName.equals("context")) {
				state = 1;
			}
			else if (rawName.equals("input")) {
				inputlist = new ArrayList<>();
				state = 3;
			}
			else if (rawName.equals("output")) {
				output = new ArrayList<>();
				state = 4;
			}
			else if (rawName.equals("addr")) {
				curaddr = AddressXML.readXML(rawName, attr, addrFactory);
				if (state == 1) {
					baseAddr = curaddr;
					state = 2;
				}
				else if (state == 2) {
					callAddr = curaddr;
				}
				else if (state == 3) {
					int size = SpecXmlUtils.decodeInt(attr.getValue("size"));
					Varnode vn = new Varnode(curaddr, size);
					inputlist.add(vn);
				}
				else if (state == 4) {
					int size = SpecXmlUtils.decodeInt(attr.getValue("size"));
					Varnode vn = new Varnode(curaddr, size);
					output.add(vn);
				}
			}
			else {
				throw new SAXException("Unrecognized inject tag: " + rawName);
			}

		}
	}

	public SleighLanguage language;
	public Address baseAddr;		// Base address of op (call,userop) causing the inject
	public Address nextAddr;		// Address of next instruction following the injecting instruction
	public Address callAddr;		// For a call inject, the address of the function being called
	public Address refAddr;
	public ArrayList<Varnode> inputlist;	// Input parameters for the injection
	public ArrayList<Varnode> output;		// Output parameters

	public InjectContext() {
	}

	public void restoreXml(SAXParser parser, String xml, AddressFactory addrFactory)
			throws PcodeXMLException {
		Handler handler = new Handler(addrFactory);
		try {
			parser.parse(new InputSource(new StringReader(xml)), handler);
		}
		catch (SAXException e) {
			throw new PcodeXMLException("Problem parsing inject context: " + e.getMessage());
		}
		catch (IOException e) {
			throw new PcodeXMLException("Problem parsing inject context: " + e.getMessage());
		}

	}
}
