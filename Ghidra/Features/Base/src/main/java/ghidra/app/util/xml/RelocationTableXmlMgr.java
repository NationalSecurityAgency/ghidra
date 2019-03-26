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

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.util.Iterator;
import java.util.StringTokenizer;

class RelocationTableXmlMgr {

	private Program program;
	private MessageLog log;

	RelocationTableXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.log = log;
	}

	void read(XmlPullParser parser, TaskMonitor monitor) throws CancelledException {
		RelocationTable relocTable = program.getRelocationTable();
		AddressFactory factory = program.getAddressFactory();

		XmlElement element = parser.next();
		while (true) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			element = parser.next();
			if (!element.getName().equals("RELOCATION")) {
				break;
			}
			try {
				String addrStr = element.getAttribute("ADDRESS");
				if (addrStr == null) {
					log.appendMsg("relocation address not specified.");
					continue;
				}
				Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
				if (addr == null) {
					throw new AddressFormatException("Incompatible Relocation Address: " + addrStr);
				}
				int type = XmlUtilities.parseInt(element.getAttribute("TYPE"));
				long[] values = unpackLongs(element.getAttribute("VALUE"));
				byte[] bytes = unpackBytes(element.getAttribute("BYTES"));
				String symbolName = element.getAttribute("SYMBOL_NAME");

				relocTable.add(addr, type, values, bytes, symbolName);
			}
			catch (Exception e) {
				log.appendException(e);
			}
			finally {
				//always consume the RELOCATION end tag...
				element = parser.next();
			}
		}
	}

	private long[] unpackLongs(String attrValue) {
		StringTokenizer st = new StringTokenizer(attrValue, ",");
		long[] values = new long[st.countTokens()];
		int index = 0;
		while (st.hasMoreTokens()) {
			values[index++] = XmlUtilities.parseLong(st.nextToken());
		}
		return values;
	}

	private byte[] unpackBytes(String attrValue) {
		if (attrValue == null) {
			return null;
		}
		StringTokenizer st = new StringTokenizer(attrValue, ",");
		byte[] values = new byte[st.countTokens()];
		int index = 0;
		while (st.hasMoreTokens()) {
			values[index++] = (byte) XmlUtilities.parseInt(st.nextToken());
		}
		return values;
	}

	private String pack(long[] values) {
		if (values == null || values.length == 0) {
			return "";
		}
		StringBuffer buf = new StringBuffer();
		for (long v : values) {
			if (buf.length() != 0) {
				buf.append(',');
			}
			buf.append("0x" + Long.toHexString(v));
		}
		return buf.toString();
	}

	private String pack(byte[] values) {
		if (values == null || values.length == 0) {
			return "";
		}
		StringBuffer buf = new StringBuffer();
		for (byte v : values) {
			if (buf.length() != 0) {
				buf.append(',');
			}
			buf.append("0x" + Integer.toHexString(v & 0xff));
		}
		return buf.toString();
	}

	void write(XmlWriter writer, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Writing RELOCATION TABLE ...");

		writer.startElement("RELOCATION_TABLE");

		Iterator<Relocation> iter = program.getRelocationTable().getRelocations();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			Relocation reloc = iter.next();

			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(reloc.getAddress()));
			attrs.addAttribute("TYPE", reloc.getType(), true);
			attrs.addAttribute("VALUE", pack(reloc.getValues()));
			attrs.addAttribute("BYTES", pack(reloc.getBytes()));
			attrs.addAttribute("SYMBOL_NAME", reloc.getSymbolName());

			writer.startElement("RELOCATION", attrs);
			writer.endElement("RELOCATION");
		}

		writer.endElement("RELOCATION_TABLE");
	}

}
