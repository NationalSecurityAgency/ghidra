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

import java.util.HashSet;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.datatype.microsoft.GuidDataType;
import ghidra.app.util.datatype.microsoft.GuidUtil;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class ApplySymbols {
//	private static final String MS_VF_TABLE_PREFIX = "??_7";
//	private static final String MS_VB_TABLE_PREFIX = "??_8";
//	private static final String MS_STRING_PREFIX = "??_C@_";

	private ApplySymbols() {
		// static use only
	}

	static void applyTo(PdbParser pdbParser, XmlPullParser xmlParser, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		Program program = pdbParser.getProgram();
		FunctionManager functionManager = program.getFunctionManager();
		Set<String> tagSet = new HashSet<>();
		AddressSet disassembleSet = new AddressSet();

		while (xmlParser.hasNext()) {
			if (monitor.isCancelled()) {
				return;
			}
			XmlElement elem = xmlParser.next();
			if (elem.isEnd() && elem.getName().equals("table")) {
				break;
			}
			xmlParser.next();//skip end element

			String name = elem.getAttribute("name");
			int addr = XmlUtilities.parseInt(elem.getAttribute("address"));
			int length = XmlUtilities.parseInt(elem.getAttribute("length"));
			String tag = elem.getAttribute("tag");
//			String kind = elem.getAttribute("kind");
			String datatype =
				SymbolUtilities.replaceInvalidChars(elem.getAttribute("datatype"), false);
//			String undecorated  =  elem.getAttribute("undecorated");

			tagSet.add(tag);

			if (name.length() == 0 || addr == 0) {
				continue;
			}

			// We do not need additional symbols for Functions;
			// we already have what we need from the Functions section.
			if ("Function".equals(tag)) {
				continue;
			}

			Address address = PdbUtil.reladdr(program, addr);
			monitor.setMessage("Applying symbol at " + address + "...");

			boolean forcePrimary = shouldForcePrimarySymbol(program, address);

			// Only create pre-comment from Block symbol
			if ("Block".equals(tag)) {
				String preComment = "PDB: Start of Block";
				if (!"NONAME".equals(name)) {
					preComment += " (" + name + ")";
				}
				PdbUtil.appendComment(program, address, preComment, CodeUnit.PRE_COMMENT);
				continue;
			}

			// Place compiler generated symbols (e.g., $LN9) within containing function when possible
			if (name.startsWith("$") && !name.contains(Namespace.DELIMITER)) {
				Function f = functionManager.getFunctionContaining(address);
				if (f != null && !f.getName().equals(name)) {
					name = NamespaceUtils.getNamespaceQualifiedName(f, name, true);
				}
			}

			if (length == 0) {
				// avoid creating symbol which may correspond to inline function code
				PdbUtil.appendComment(program, address, "Symbol Ref: {@symbol " + name + "}",
					CodeUnit.PRE_COMMENT);
				continue;
			}

			// Don't create label for Data since a separate symbol should also exist with a better name
			if (!"Data".equals(tag)) {
				pdbParser.createSymbol(address, name, forcePrimary, log);
			}

			////////////
			// Commented out the following for now, because it appears to be doing things it 
			// shouldn't. Many of the things are very loosely speculative.
			// TODO Someone needs to determine if the attempted functionality can be properly refined.
			////////////
//			if (name.startsWith(MS_VF_TABLE_PREFIX)) {
//// TODO: Should this be handled by the demangler instead of here?
//				//MemBuffer mbuf = new MemoryBufferImpl(program.getMemory(), address);
//				PointerDataType pointer = new PointerDataType(program.getDataTypeManager());
//				int nPtrs = length / pointer.getLength();
//				for (int i = 0; i < nPtrs; ++i) {
//					pdbParser.createData(address, pointer, log, monitor);
//					address = address.add(pointer.getLength());
//				}
//			}
//			else if (name.startsWith(MS_VB_TABLE_PREFIX)) {
//// TODO: Should this be handled by the demangler instead of here?
//				DWordDataType dword = DWordDataType.dataType;
//				int nDwords = length / dword.getLength();
//				for (int i = 0; i < nDwords; ++i) {
//					pdbParser.createData(address, dword, log, monitor);
//					address = address.add(dword.getLength());
//				}
//			}
//			else 
//			if (name.startsWith(MS_STRING_PREFIX)) {
// TODO: Should this be handled by the demangler instead of here?
//				boolean isUnicode = isUnicode(name);
//				pdbParser.createString(isUnicode, address, log);
//			}
			////////////
			// Commented out the following for now, because it appears to be doing things it 
			// shouldn't. Many of the things are very loosely speculative.
			// TODO Someone needs to determine if the attempted functionality can be properly refined.
			////////////
//			else if (PdbUtil.isFunction(program, name, address, length)) {
//				disassembleSet.add(new AddressRangeImpl(address, address));
//			}
//			else if (name.startsWith("__sz_")) {
//				pdbParser.createString(false, address, log, monitor);
//			}
//			else if (name.startsWith("__real")) {
//				if (length == 4) {
//					pdbParser.createData(address, FloatDataType.dataType, log, monitor);
//				}
//				else {
//					pdbParser.createData(address, DoubleDataType.dataType, log, monitor);
//				}
//			}
			if (GuidUtil.isGuidLabel(program, address, name)) {
				pdbParser.createData(address, new GuidDataType(), log);
			}
			else if (tag.equals("Data")) {
				if (datatype.length() == 0) {
					continue;
				}
				pdbParser.createData(address, datatype, log);
			}
		}

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			if (!block.isExecute()) {
				disassembleSet.deleteRange(block.getStart(), block.getEnd());
			}
		}
		monitor.setMessage("Disassemble...");
		DisassembleCommand cmd = new DisassembleCommand(disassembleSet, null, true);
		cmd.applyTo(program, monitor);

	}

	private static boolean shouldForcePrimarySymbol(Program program, Address address) {
		Symbol primarySymbol = program.getSymbolTable().getPrimarySymbol(address);
		if (primarySymbol != null) {
			SourceType primarySymbolSource = primarySymbol.getSource();

			if (primarySymbolSource.equals(SourceType.ANALYSIS)) {
				return true;
			}
		}
		return false;
	}

//	private static boolean isUnicode(String name) {
//		if (name.startsWith(MS_STRING_PREFIX)) {
//			if (name.charAt(MS_STRING_PREFIX.length()) == '1') {
//				return true;
//			}
//		}
//		return false;
//	}

}
