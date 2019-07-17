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
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlAttributes;
import ghidra.util.xml.XmlWriter;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class CodeXmlMgr implements DisassemblerMessageListener {
	private Program program;
	private MessageLog log;

	CodeXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.log = log;
	}

/////////////////////////////////////////////////////////////////////////////////////
//                         XML WRITE CURRENT DTD                                   //
/////////////////////////////////////////////////////////////////////////////////////

	void write(XmlWriter writer, AddressSetView set, TaskMonitor monitor) throws CancelledException {
		monitor.setMessage("Writing CODE ...");
		writer.startElement("CODE");
		exportCode(writer, set, monitor);
		writer.endElement("CODE");
	}

	private void exportCode(XmlWriter writer, AddressSetView set, TaskMonitor monitor)
			throws CancelledException {
		monitor.setMessage("Exporting Code Blocks....");

		InstructionIterator it = null;
		if (set == null) {
			it = program.getListing().getInstructions(true);
		}
		else {
			it = program.getListing().getInstructions(set, true);
		}

		if (it.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			Instruction inst = it.next();
			Address start = inst.getMinAddress();
			Address end = inst.getMaxAddress();
			while (it.hasNext()) {
				inst = it.next();
				if (!end.isSuccessor(inst.getMinAddress())) {
					exportCodeBlock(writer, start, end);
					start = inst.getMinAddress();
				}
				end = inst.getMaxAddress();
				if (monitor.isCancelled())
					break;
			}
			exportCodeBlock(writer, start, end);
		}
	}

	private void exportCodeBlock(XmlWriter writer, Address start, Address end) {
		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("START", XmlProgramUtilities.toString(start));
		attrs.addAttribute("END", XmlProgramUtilities.toString(end));

		writer.startElement("CODE_BLOCK", attrs);
		writer.endElement("CODE_BLOCK");
	}

/////////////////////////////////////////////////////////////////////////////////////
//                         XML READ CURRENT DTD                                    //
/////////////////////////////////////////////////////////////////////////////////////

	void read(XmlPullParser parser, TaskMonitor monitor) throws AddressFormatException,
			CancelledException {

		AddressSet set = new AddressSet();

		XmlElement element = parser.next();
		element = parser.next();
		while (element.getName().equals("CODE_BLOCK")) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			processCodeBlock(parser, element, monitor, set);
			element = parser.next();
			element = parser.next();
		}
		// assert element.getName() == "CODE"

		AddressSet disset = set.intersect(program.getMemory());

		if (!disset.equals(set)) {
			log.appendMsg("Disassembly address set changed to " + disset.toString());
		}

		disassemble(disset, monitor);
	}

	private void processCodeBlock(XmlPullParser parser, XmlElement element, TaskMonitor monitor,
			AddressSet set) throws AddressFormatException {

		AddressFactory af = program.getAddressFactory();
		String startAddrStr = element.getAttribute("START");
		String endAddrStr = element.getAttribute("END");
		Address start = XmlProgramUtilities.parseAddress(af, startAddrStr);
		Address end = XmlProgramUtilities.parseAddress(af, endAddrStr);
		if (start == null || end == null) {
			throw new AddressFormatException("Incompatible Code Block Address Range: [" +
				startAddrStr + "," + endAddrStr + "]");
		}
		set.addRange(start, end);
	}

	private void disassemble(AddressSet set, TaskMonitor monitor) {
		Disassembler disassembler = Disassembler.getDisassembler(program, monitor, this);
		try {
			Listing listing = program.getListing();
			while (!set.isEmpty() && !monitor.isCancelled()) {
				Address start = set.getMinAddress();
				AddressSet disset = disassembler.disassemble(start, set);
				if (disset.isEmpty()) {
					Instruction instr = listing.getInstructionAt(start);
					if (instr == null) {
						AddressRange skipRange = set.iterator().next();
						log.appendMsg("Expected valid Instruction at " + start);
						log.appendMsg("...skipping code range " + skipRange.getMinAddress() +
							" to " + skipRange.getMaxAddress());
						set.delete(skipRange);
					}
					else {
						set.deleteRange(instr.getMinAddress(), instr.getMaxAddress());
					}
				}
				else {
					set.delete(disset);
				}
			}
		}
		catch (Exception e) {
			log.appendMsg("Error during disassembly: " + e.getMessage());
		}
	}

	@Override
	public void disassembleMessageReported(String msg) {
		log.appendMsg("Error from disassembler: " + msg);
	}

}
