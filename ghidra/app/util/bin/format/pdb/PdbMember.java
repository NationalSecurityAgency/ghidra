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

import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlTreeNode;

final class PdbMember {
	final String memberName;
	final String memberDataTypeName;
	final int memberOffset;
	final String memberKind;
	final int memberLength;

	PdbMember(XmlTreeNode node, TaskMonitor monitor) {
		this(node.getStartElement(), monitor);
	}

	PdbMember(XmlElement element, TaskMonitor monitor) {
		// TODO: Need to examine consistency of renaming names/data types for space removal across
		//  all of PDB.
		memberName = SymbolUtilities.replaceInvalidChars(element.getAttribute("name"), false);
		memberDataTypeName = element.getAttribute("datatype");
		memberOffset = XmlUtilities.parseInt(element.getAttribute("offset"));
		memberKind = element.getAttribute("kind");
		memberLength = XmlUtilities.parseInt(element.getAttribute("length"));
	}

}
