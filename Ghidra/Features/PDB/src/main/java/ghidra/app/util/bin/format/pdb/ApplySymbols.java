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
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.datatype.microsoft.GuidDataType;
import ghidra.app.util.datatype.microsoft.GuidUtil;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
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
		String className = "";
		boolean processingClass = false;
		int vfCount = 0;
		int indexSinceStart = 0;
		LinkedHashMap<PointerDataType, String> vftableList = null;
		Set<String> processedClasses = new HashSet<>();

		DataTypeManager dtm = program.getDataTypeManager();
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
			String kind = elem.getAttribute("kind");
			String datatype =
				SymbolUtilities.replaceInvalidChars(elem.getAttribute("datatype"), false);
			String undecorated = elem.getAttribute("undecorated");

			tagSet.add(tag);

			// Process potential vfuncs from the symbols
			// We cannot determine vtables solely by symbol list since this will include
			// defined functions. This will generate a list of potential vfuncs for
			// confirmation against known addresses.
			if (processingClass) {
				monitor.setProgress(processedClasses.size());
				monitor.setMaximum(pdbParser.numClasses());
				monitor.setIndeterminate(false);
				if (!className.isEmpty())
					monitor.setMessage("Processing vfuncs for " + className);
				else
					monitor.setMessage("Processing vfuncs");

				if ("Member".equals(tag) || indexSinceStart >= pdbParser.numClassMembers(className)) {
					// We saw potential vfuncs but now we're seeing nodes like members
					processingClass = false;
				} else if ("Function".equals(tag)) {
					if (!undecorated.isEmpty() && pdbParser.classVfuncIndex(className, name) != -1) {
						undecorated = cleanUpUndecorated(undecorated);
						FunctionDefinitionDataType dt = pdbParser.createFuncDef(name, className, undecorated, log);
						dt = (dt != null) ? dt
								: pdbParser.createFuncDef(name, className,
										String.format("undefined vFunc_%02x(void)", vfCount), log);
						vftableList.put(new PointerDataType(dt), String.format("%02x: %s", vfCount, undecorated));
						vfCount++;
					}
					continue;
				}
				indexSinceStart++;
			} else if (vfuncDetectable(pdbParser, name, tag, kind) && !processedClasses.contains(name)) {
				// begin processing
				className = name;
				vftableList = new LinkedHashMap<PointerDataType, String>();
				processingClass = true;
				vfCount = 0;
				indexSinceStart = 0;
				continue;
			}
			// class has ended
			if (!className.isEmpty() && !processingClass) {
				// finished processing a class, build vftable
				createVFuncTable(pdbParser, className, vftableList, dtm);
				processedClasses.add(className);
				className = "";
				vfCount = 0;
				vftableList = null;
				indexSinceStart = 0;
				continue;
			}

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

	/**
	 * Whether its possible to find new vfuncs for the class 
	 * from the symbols table.
	 * 
	 * @param pdbParser parser with cached data types
	 * @param className name of class
	 * @param tag the tag attribute
	 * @param kind the kind attribute
	 * @return boolean
	 */
	private static boolean vfuncDetectable(PdbParser pdbParser, String className, String tag, String kind) {
		return pdbParser.getCachedDataType(className) != null // Known classes have a cachedDataType
				// Symbol with tag and kind is start of class vfuncs
				&& "UserDefinedType".equals(tag) && "Class".equals(kind);
	}

	/**
	 * Clean up MSVC undecorated pdb attribute string for further processing.
	 * 
	 * @param undecorated PDB signature to be cleaned
	 * @return returns cleaned up string
	 */
	private static String cleanUpUndecorated(String undecorated) {
		List<String> removals = List.of("class ", "struct ", "union ", "const ", "public: ", "private: ",
				"protected: ", "virtual ", "static ");
		LinkedHashMap<String, String> replacements = new LinkedHashMap<String, String>() {
			{
				put("& const", "");
				put("&", "");
				put("\\s+\\*", " *");
				put("\\s+\\*>", "*>");
				put("\\s+\\*,", "*,");
				put(">\\s+\\*>", ">*");
				put(">\\s+(?=>)", ">");
				put("\\s+,", ",");
				put("<enum ", "<");
				put("^enum ", "");
				put(" ?const> ", ">");
				put(" ?const, ", ",");
				put("\\)\\s+", ")");
				put("unsigned __int64", "uint64_t");
				put("signed __int64", "int64_t");
				put("char8_t", "uchar");
			}
		};
		for (String removal : removals) {
			undecorated = undecorated.replaceAll(removal, "");
		}
		for (Map.Entry<String, String> entry : replacements.entrySet()) {
			undecorated = undecorated.replaceAll(entry.getKey(), entry.getValue());
		}
		return undecorated;
	}

	/**
	 * Create a potential vfunctable for the className. This vfunctable
	 * will have both vfuncs and non-vfuncs. The RTTI will need to
	 * determine when to stop.
	 * 
	 * @param pdbParser pdbParser handling the pdb
	 * @param className the name of the class
	 * @param vftableList a list of poiners to function definitions
	 * @param dtm the data type mamanager to create the vftable in
	 */
	private static void createVFuncTable(PdbParser pdbParser, String className,
			LinkedHashMap<PointerDataType, String> vftableList, DataTypeManager dtm) {
		if (vftableList != null && !vftableList.isEmpty()) {
			Structure vftable = pdbParser.createStructure(String.format("%s::vftable", className),0);
			for (Map.Entry<PointerDataType, String> entry : vftableList.entrySet()) {
				vftable.add(entry.getKey(), entry.getKey().getName(), entry.getValue());
			}
			vftable.setDescription("Potential list of vfuncs; end may not be vfuncs");
			dtm.addDataType(vftable, null);
		}
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
