/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.xml;

import ghidra.app.util.importer.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.*;
import ghidra.util.task.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

import java.io.*;
import java.util.*;

/**
 * XML manager for Equates.
 */
class EquatesXmlMgr {
	private MessageLog log;
	private EquateTable equateTable;

	EquatesXmlMgr(Program program, MessageLog log) {
		this.log = log;	
		this.equateTable = program.getEquateTable();
	}
	
	/**
	 * Process the entry point section of the XML file.
	 * @param parser xml reader
	 * @param monitor monitor that can be canceled
	 */
	void read(XmlPullParser parser, TaskMonitor monitor) throws CancelledException { 
		XmlElement element = parser.next();
		while (true) {
			if (monitor.isCancelled()) {
				throw new CancelledException();	
			}
			element = parser.peek();
			if (element == null || !element.getName().equals("EQUATE_GROUP")) {
				break;
			}
			processEquateGroup(parser, monitor);
		}
		element = parser.next();//consume last EQUATES tag
	} 
	
	/**
	 * Write out the XML for the Equates.
	 * @param writer writer for XML
	 * @param set address set that is either the entire program or a selection
	 * @param monitor monitor that can be canceled
	 * should be written
	 * @throws IOException
	 */
	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor)  throws CancelledException {
		monitor.setMessage("Writing EQUATES ...");
		writer.startElement("EQUATES");

		writer.startElement("EQUATE_GROUP");
		Iterator<Equate> iter = equateTable.getEquates();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();	
			}
			Equate equate = iter.next();
			writeEquate(writer, equate, set);
		}	
		writer.endElement("EQUATE_GROUP");
		
		writer.endElement("EQUATES");
	}
			
	private void processEquateGroup(XmlPullParser parser, TaskMonitor monitor) {
		XmlElement element = parser.next();
		while (!monitor.isCancelled()) {
			element = parser.peek();

			if (element.getName().equals("DISPLAY_SETTINGS") ||
				element.getName().equals("REGULAR_CMT") || 
				element.getName().equals("REPEATABLE_CMT") || 
				element.getName().equals("BIT_MASK")) {

				element = parser.next();
				element = parser.next();
				continue;
			}
			if (!element.getName().equals("EQUATE")) {
				break;
			}
			processEquate(parser, element);
		}
		element = parser.next();//consume end EQUATES_GROUP tag
	}

	private void processEquate(XmlPullParser parser, XmlElement element) {
		if (!element.isStart()) {
			return;
		}
		element = parser.next();//consume EQUATE start tag...

		String name = element.getAttribute("NAME");
		long value = XmlUtilities.parseLong(element.getAttribute("VALUE"));

		try {
			equateTable.createEquate(name, value);
		}
		catch (DuplicateNameException e) {
			Equate eq = equateTable.getEquate(name);
			long prevVal = eq.getValue();
			if (prevVal != value) {
				log.appendMsg("Cannot create equate ["+name+
								"] with value ["+Long.toHexString(value)+
								"]; previously defined with value ["+
								Long.toHexString(prevVal)+"]");
			}
		}
		catch (Exception e) {
			log.appendException(e);
		}

		element = parser.peek();
		if (element.getName().equals("REGULAR_CMT")) {
			element = parser.next();
			element = parser.next();
		}
		element = parser.peek();
		if (element.getName().equals("REPEATABLE_CMT")) {
			element = parser.next();
			element = parser.next();
		}

		element = parser.next();//consume EQUATE end tag...
	}

	private void writeEquate(XmlWriter writer, Equate equate, 
							 AddressSetView set) {
		boolean okToWrite=false;
		if (set == null) {
			okToWrite=true;
		}
		else {
			EquateReference[] refs = equate.getReferences();
			for (int i=0; i<refs.length; ++i) {
				if (set.contains(refs[i].getAddress())) {
					okToWrite = true;
					break;
				}
			}
		}
		if (okToWrite) {
			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("NAME", equate.getName());
			attrs.addAttribute("VALUE", equate.getValue(), true);
			writer.startElement("EQUATE", attrs);
			writer.endElement("EQUATE");
		}
	}
	
}
