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
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

import java.io.*;
import java.util.*;

/**
 * XML manager for External Entry Points.
 */
class ExtEntryPointXmlMgr {
	private MessageLog log;
	private AddressFactory factory;
	private SymbolTable symbolTable;

	ExtEntryPointXmlMgr(Program program, MessageLog log) {
		this.log = log;	
		symbolTable = program.getSymbolTable();
		factory = program.getAddressFactory();
	}

	/**
	 * Process the entry point section of the XML file.
	 * @param parser xml reader
	 * @param monitor monitor that can be canceled
	 */
	void read(XmlPullParser parser, TaskMonitor monitor) throws AddressFormatException, CancelledException { 
		XmlElement element = parser.next();
		while (true) {
			if (monitor.isCancelled()) {
				throw new CancelledException();	
			}
			element = parser.peek();
			if (!element.getName().equals("PROGRAM_ENTRY_POINT")) {
				break;
			}
			element = parser.next();    	
			String addrStr = element.getAttribute("ADDRESS");
			Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
			if (addr == null) {
				throw new AddressFormatException("Incompatible Entry Point Address: "+addrStr);
			}
			try {
				symbolTable.addExternalEntryPoint(addr);
			}
			catch (Exception e) {
				log.appendException(e);
			}
			finally {
				element = parser.next();
			}
		}
		element = parser.next();
	}

	/**
	 * Write out the XML for the external entry points.
	 * @param writer writer for XML
	 * @param set address set that is either the entire program or a selection
	 * @param monitor monitor that can be canceled
	 * should be written
	 * @throws IOException
	 */
	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Getting ENTRY POINTS ...");
		writer.startElement("PROGRAM_ENTRY_POINTS"); 
		AddressIterator iter = symbolTable.getExternalEntryPointIterator();
		ArrayList<Address> list = new ArrayList<Address>();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();	
			}
			list.add(iter.next());

		}
		monitor.setMessage("Sorting ENTRY POINTS ...");
		Collections.sort(list);
		monitor.setMessage("Writing ENTRY POINTS ...");
		Iterator<Address> listIter = list.iterator();
		while (listIter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();	
			}
		    Address addr = listIter.next();
			if (set == null || set.contains(addr)) {
				XmlAttributes attrs = new XmlAttributes();
				attrs.addAttribute("ADDRESS", addr.toString()); 
				writer.startElement("PROGRAM_ENTRY_POINT", attrs);
				writer.endElement("PROGRAM_ENTRY_POINT");
			}
		}
		writer.endElement("PROGRAM_ENTRY_POINTS");
	}

}
