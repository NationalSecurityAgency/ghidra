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
package ghidra.app.util.bin.format.pdb;

import java.io.File;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class ApplyLineNumbers {
	//private PdbParserNEW pdbParser;
	private XmlPullParser xmlParser;
	private Program program;

	ApplyLineNumbers(PdbParser pdbParser, XmlPullParser xmlParser, Program program) {
		//this.pdbParser = pdbParser;
		this.xmlParser = xmlParser;
		this.program = program;
	}

	void applyTo(TaskMonitor monitor, MessageLog log) {
		while (xmlParser.hasNext()) {
			if (monitor.isCancelled()) {
				return;
			}
			XmlElement elem = xmlParser.peek();
			if (elem.isEnd() && elem.getName().equals("function")) {
				break;
			}
			elem = xmlParser.next();//line number start tag
			String sourcefileName = elem.getAttribute("source_file");

			int start = XmlUtilities.parseInt(elem.getAttribute("start"));
			int addr = XmlUtilities.parseInt(elem.getAttribute("addr"));
			Address address = PdbUtil.reladdr(program, addr);
			// The following line was changed from getCodeUnitAt(address) to
			// getCodeUnitContaining(address) in order to fix an issue where the PDB associates
			// a line number with base part of an instruction instead of the prefix part of an
			// instruction.  In particular, Microsoft emits a "REP RET" (f3 c3) sequence, where
			// the "REP" is an instruction prefix, in order to avoid a branch prediction penalty
			// for AMD processors.  However, Microsoft associates the line number of the
			// instruction with the address of the "RET" (c3) instead of with the address of the
			// "REP" (f3) portion (beginning) of the instruction.
			CodeUnit cu = program.getListing().getCodeUnitContaining(address);
			if (cu == null) {
				log.appendMsg("PDB",
					"Could not apply source code line number (no code unit found at " + address +
						")");
			}
			else {
				cu.setProperty("Source Path", sourcefileName);
				cu.setProperty("Source File", new File(sourcefileName).getName());
				cu.setProperty("Source Line", start);
			}
			//String comment = sourcefile.getName()+":"+start;
			//setComment(CodeUnit.PRE_COMMENT, program.getListing(), address, comment);
			elem = xmlParser.next();//line number end tag
		}
	}
}
