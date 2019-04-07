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
package ghidra.macosx.analyzers;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.MachoLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class CFStringAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "CFStrings";
	private static final String DESCRIPTION =
		"Parses CFString section in MachO files and inserts helpful EOL comment on all xrefs";

	private static final String CF_STRING_LABEL_PREFIX = "cf_";
	private static final String CFSTRING = "__cfstring";

	public CFStringAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		DataType dataType = getDataType(program);

		MemoryBlock block = program.getMemory().getBlock(CFSTRING);
		if (block == null) {
			return false;
		}
		Address currentAddress = block.getStart();
		Address endAddress = block.getEnd();
		Listing listing = program.getListing();
		listing.clearCodeUnits(currentAddress, endAddress, true, monitor);

		while (!monitor.isCancelled()) {
			Address structEnd = currentAddress.add(dataType.getLength() - 1);

			if (structEnd.compareTo(block.getEnd()) > 0) {
				break;
			}

			try {
				Data data = program.getListing().createData(currentAddress, dataType);
				Address strAddress = (Address) data.getComponent(2).getValue();

				Scalar lengthScalar = (Scalar) data.getComponent(3).getValue();
				int length = (int) lengthScalar.getValue();

				Data stringData = program.getListing().getDataAt(strAddress);
				if (stringData == null) {
					continue;
				}
				if (!(stringData.getValue() instanceof String)) {
					try {
						listing.clearCodeUnits(strAddress, strAddress.add(length), true);
						stringData = listing.createData(strAddress, StringDataType.dataType);
					}
					catch (Exception e) {
						log.appendMsg("Error creating string at address " + strAddress);
					}

					if (!(stringData.getValue() instanceof String)) {
						continue;
					}
				}

// TODO: Creation of label should be necessary
//  Case1: at string you can see the string (or dynamic label if there is a reference)
//  Case2: at reference operand you will see dynamic string label
//  Case3: looking for specific string - use Defined Data window and filter on data type and string fragment

				String cFString = (String) stringData.getValue();

				String symbolString = makeLabel(cFString);

				String comment = makeComment(cFString);

				program.getListing().setComment(currentAddress, CodeUnit.REPEATABLE_COMMENT,
					"\"" + comment + "\",00");

				if (program.getSymbolTable().getGlobalSymbol(symbolString,
					currentAddress) != null) {
					continue;
				}

				Symbol mine = program.getSymbolTable().createLabel(currentAddress, symbolString,
					SourceType.ANALYSIS);
				mine.setPrimary();
			}
			catch (CodeUnitInsertionException e) {
				log.appendException(e);
				return false;
			}
			catch (DataTypeConflictException e) {
				log.appendException(e);
				return false;
			}
			catch (InvalidInputException e) {
				log.appendException(e);
				// return false;
				// Returning here causes the analyzer to quit early if it encounters a CFString
				// that is a possible default name (like "a") even if it is valid data.
			}
			finally {
				currentAddress = currentAddress.add(dataType.getLength());
			}
		}

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isMachOAndContainsCFStrings(program);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return isMachOAndContainsCFStrings(program);
	}

	private boolean isMachOAndContainsCFStrings(Program program) {
		if (program.getExecutableFormat().equals(MachoLoader.MACH_O_NAME)) {
			MemoryBlock[] blocks = program.getMemory().getBlocks();
			for (MemoryBlock block : blocks) {
				if (block.getName().equals(CFSTRING)) {
					return true;
				}
			}
		}
		return false;
	}

	private DataType getDataType(Program program) {
		Structure structure = new StructureDataType("cfstringStruct", 0);
		boolean is64Bit = program.getDefaultPointerSize() == 8;
		if (is64Bit) {
			structure.add(QWordDataType.dataType);
			structure.add(QWordDataType.dataType);
			structure.add(PointerDataType.dataType, 8);
			structure.add(LongDataType.dataType, 8);
		}
		else {
			structure.add(DWordDataType.dataType);
			structure.add(DWordDataType.dataType);
			structure.add(PointerDataType.dataType);
			structure.add(IntegerDataType.dataType);
		}
		return structure;

	}

	private String makeComment(String cFString) {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < cFString.length(); i++) {
			char c = cFString.charAt(i);
			switch (c) {
				case '\t':
					buf.append("\\t");
					break;
				case '\n':
					buf.append("\\n");
					break;
				case '\r':
					buf.append("\\r");
					break;
				default:
					if (c >= 0x20 && c < 0x80) {
						buf.append(c);
					}
					else {
						buf.append('.');
					}
					break;
			}
		}
		return buf.toString();
	}

	private String makeLabel(String cFString) {
		if (cFString.length() == 0) {
			return CF_STRING_LABEL_PREFIX + "\"\"";
		}

		StringBuffer buf = new StringBuffer();

// don't use 's', since we are creating a label for a structure and not for a string
//		buf.append('s');

		for (int i = 0; i < cFString.length(); i++) {
			char c = cFString.charAt(i);
			if (c > 0x20 && c < 0x80) {
				buf.append(c);
			}
		}

		if (buf.length() == 0) {
			if (doesStringContainAllSameChars(cFString)) {
				switch (cFString.charAt(0)) {
					case '\t':
						buf.append("tab(s)");
						break;
					case '\n':
						buf.append("newline(s)");
						break;
					case '\r':
						buf.append("creturn(s)");
						break;
					case ' ':
						buf.append("space(s)");
						break;
					default:
						buf.append('.');
						break;
				}
			}
			else {
				buf.append("format(s)");
			}
		}

		buf.insert(0, CF_STRING_LABEL_PREFIX);

		return buf.toString();
	}

	private boolean doesStringContainAllSameChars(String string) {
		char firstChar = string.charAt(0);
		for (int i = 1; i < string.length(); i++) {
			if (string.charAt(i) != firstChar) {
				return false;
			}
		}
		return true;
	}
}
