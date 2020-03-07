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

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class ApplyEnums {

	private ApplyEnums() {
		// static use only
	}

	/**
	 * Perform parsing and applying of enum datatypes
	 * @param pdbParser PDB parser object
	 * @param xmlParser XML parser position immediately after the enums start element
	 * @param monitor task monitor
	 * @param log message log
	 * @throws CancelledException if task cancelled
	 */
	static void applyTo(XmlPullParser xmlParser, PdbParser pdbParser, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		monitor.setMessage("Applying enums...");
		while (xmlParser.hasNext()) {
			monitor.checkCanceled();
			XmlElement elem = xmlParser.next();

			if (elem.isEnd() && elem.getName().equals("enums")) {
				break;
			}

			String name = SymbolUtilities.replaceInvalidChars(elem.getAttribute("name"), false);
			int length = XmlUtilities.parseInt(elem.getAttribute("length"));
			EnumDataType enumdt = pdbParser.createEnum(name, length);

			while (xmlParser.hasNext()) {
				if (monitor.isCancelled()) {
					break;
				}
				elem = xmlParser.next();
				if (elem.isEnd() && elem.getName().equals("enum")) {
					break;
				}
				applyEnumMember(enumdt, elem, monitor, log);
				xmlParser.next();//member end element
			}
			pdbParser.cacheDataType(name, enumdt); // cache with namespace-based name
			pdbParser.getProgramDataTypeManager()
					.resolve(enumdt,
						DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		}
	}

	private static void applyEnumMember(EnumDataType enumdt, XmlElement memberElem,
			TaskMonitor monitor, MessageLog log) {
		String name = SymbolUtilities.replaceInvalidChars(memberElem.getAttribute("name"), false);
		int memberValue = XmlUtilities.parseInt(memberElem.getAttribute("value"));
		try {
			enumdt.add(name, memberValue);
		}
		catch (Exception e) {
			log.appendMsg("PDB", "Enum " + enumdt.getName() + ": " + e.getMessage());
		}
	}
}
