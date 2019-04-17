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
package ghidra.app.util.xml;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class DefinedDataXmlMgr {

	private Program program;
	private MessageLog log;

	DefinedDataXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.log = log;
	}

	void read(XmlPullParser parser, Boolean overwriteData, TaskMonitor monitor)
			throws CancelledException {

		Listing listing = program.getListing();
		AddressFactory factory = program.getAddressFactory();
		DataTypeManager dataManager = listing.getDataTypeManager();
		BuiltInDataTypeManager builtInMgr = BuiltInDataTypeManager.getDataTypeManager();

		int skipCodeUnitErrors = 0;

		try {
			DtParser dtParser = new DtParser(dataManager);

			XmlElement element = parser.next(); // consume DATA start

			while (true) {
				if (monitor.isCancelled()) {
					throw new CancelledException();
				}
				element = parser.next();
				if (!element.getName().equals("DEFINED_DATA")) {
					break;
				}
				String addrStr = element.getAttribute("ADDRESS");
				if (addrStr == null) {
					log.appendMsg("Defined data: address not specified.");
					parser.discardSubTree(element);
					continue;
				}
				Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
				if (addr == null) {
					log.appendMsg("Defined data: invalid address " + addrStr);
					parser.discardSubTree(element);
					continue;
				}
				String dataTypeName = element.getAttribute("DATATYPE");
				CategoryPath path =
					element.hasAttribute("DATATYPE_NAMESPACE") ? new CategoryPath(
						element.getAttribute("DATATYPE_NAMESPACE")) : CategoryPath.ROOT;
				int size =
					element.hasAttribute("SIZE") ? XmlUtilities.parseInt(element.getAttribute("SIZE"))
							: -1;
				//size = size * factory.getDefaultAddressSpace().getAddressableUnitSize();

				DataType dt = dtParser.parseDataType(dataTypeName, path, size);
				if (dt == null) {
					log.appendMsg("Defined data: unknown datatype: " + dataTypeName +
						" in category: " + path);
					parser.discardSubTree(element);
					continue;
				}

				if (!program.getMemory().contains(addr)) {
					++skipCodeUnitErrors;
					parser.discardSubTree(element);
					continue;
				}

				try {
					if (overwriteData) {
						clearExistingData(addr, size, dt, listing);
					}

					Data data = listing.createData(addr, dt, size);

					// there was a problem in that we write "DISPLAY_SETTINGS" and
					// were reading "DISPLAY_SETTING".  Not knowing which is correct,
					// just handle both in case older Ghidra versions used the other
					if (parser.peek().getName().equals("DISPLAY_SETTING")) {
						DisplaySettingsHandler.readSettings(parser.next(), data);
						parser.next();
					}
					if (parser.peek().getName().equals("DISPLAY_SETTINGS")) {
						DisplaySettingsHandler.readSettings(parser.next(), data);
						parser.next();
					}
					if (parser.peek().getName().equals("TYPEINFO_CMT")) {
						//TODO: handle TypeInfo comment...
						parser.discardSubTree("TYPEINFO_CMT");
					}

				}
				catch (CodeUnitInsertionException e) {
					Data d = listing.getDefinedDataAt(addr);
					if (d == null || !d.getDataType().isEquivalent(dt)) {
						log.appendMsg(e.getMessage());
					}
					parser.discardSubTree(element);
					continue;
				}
				catch (Exception e) {
					log.appendException(e);
					parser.discardSubTree(element);
					continue;
				}

				parser.end(element);
			}

			if (skipCodeUnitErrors != 0) {
				log.appendMsg("Skipped " + skipCodeUnitErrors +
					" Data elements where no memory was defined");
			}
		}
		finally {
			builtInMgr.close();
		}
	}

	private void clearExistingData(Address addr, int size, DataType dt, Listing listing) {
		DumbMemBufferImpl buf = new DumbMemBufferImpl(program.getMemory(), addr);
		DataTypeInstance dti = DataTypeInstance.getDataTypeInstance(dt, buf, size);
		if (dti != null) {
			boolean doClear = false;
			Address maxAddr = addr.add(dti.getLength() - 1);
			CodeUnitIterator codeUnits = listing.getCodeUnits(new AddressSet(addr, maxAddr), true);
			while (codeUnits.hasNext()) {
				CodeUnit cu = codeUnits.next();
				if (cu instanceof Data) {
					if (((Data) cu).isDefined()) {
						doClear = true;
					}
				}
				else {
					return; // don't clear instructions
				}
			}
			if (doClear) {
				listing.clearCodeUnits(addr, maxAddr, false);
			}
		}
	}

	void write(XmlWriter writer, AddressSetView addrset, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Writing DATA ...");
		writer.startElement("DATA");

		Listing listing = program.getListing();
		DataIterator iter = listing.getDefinedData(addrset, true);
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			Data data = iter.next();

			XmlAttributes attrs = new XmlAttributes();
			attrs.addAttribute("ADDRESS", XmlProgramUtilities.toString(data.getMinAddress()));
			DataType dt = data.getDataType();
			attrs.addAttribute("DATATYPE", dt.getDisplayName());
			attrs.addAttribute("DATATYPE_NAMESPACE", dt.getCategoryPath().getPath());
			attrs.addAttribute("SIZE", data.getLength(), true);

			writer.startElement("DEFINED_DATA", attrs);

			DisplaySettingsHandler.writeSettings(writer, data);

			writer.endElement("DEFINED_DATA");
		}

		writer.endElement("DATA");
	}
}
