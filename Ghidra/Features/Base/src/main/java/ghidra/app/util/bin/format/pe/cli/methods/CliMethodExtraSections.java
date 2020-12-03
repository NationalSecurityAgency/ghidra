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
package ghidra.app.util.bin.format.pe.cli.methods;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class CliMethodExtraSections implements StructConverter {

	public static final String PATH = "/PE/CLI/Methods/ExtraSections";

	private List<ExtraSection> extraSections = new ArrayList<>();

	private class ExtraSection {
		public boolean isEHTable;
		public boolean isFat;
		public boolean hasMoreSections;
		public int dataSize;
		public boolean isFilterBasedException;

		public static final int CorILMethod_Sect_EHTable = 0x1;
		public static final int CorILMethod_Sect_OptIL = 0x2;
		public static final int CorILMethod_Sect_FatFormat = 0x40;
		public static final int CorILMethod_Sect_MoreSects = 0x80;

		public static final short COR_ILEXCEPTION_CLAUSE_EXCEPTION = 0x0000;
		public static final short COR_ILEXCEPTION_CLAUSE_FILTER = 0x0001;
		public static final short COR_ILEXCEPTION_CLAUSE_FINALLY = 0x0002;
		public static final short COR_ILEXCEPTION_CLAUSE_FAULT = 0x0004;

		public ExtraSection(BinaryReader reader) throws IOException {
			byte sectionFlags = reader.readNextByte();
			isEHTable = (sectionFlags & CorILMethod_Sect_EHTable) == CorILMethod_Sect_EHTable;
			isFat = ((sectionFlags & CorILMethod_Sect_FatFormat) == CorILMethod_Sect_FatFormat);
			hasMoreSections =
				((sectionFlags & CorILMethod_Sect_MoreSects) == CorILMethod_Sect_MoreSects);

			// Read size
			if (isFat) {
				// This seems counterintuitive but it looks like they're ordering bytes like this
				byte firstSize = reader.readNextByte();
				short secondThirdSize = reader.readNextShort();
				dataSize = (secondThirdSize << 8) + (firstSize & 0xff);
			}
			else {
				dataSize = reader.readNextByte();
			}

			// Read Flags for exception handlers
			if (isFat) {
				int exceptionHandlingFlags = reader.readNextInt();
				isFilterBasedException = ((exceptionHandlingFlags &
					COR_ILEXCEPTION_CLAUSE_FILTER) == COR_ILEXCEPTION_CLAUSE_FILTER);
			}
			else {
				short exceptionHandlingFlags = reader.readNextShort();
				isFilterBasedException = ((exceptionHandlingFlags &
					COR_ILEXCEPTION_CLAUSE_FILTER) == COR_ILEXCEPTION_CLAUSE_FILTER);
			}
		}

		public StructureDataType getSmallExceptionClauseDataType() {
			StructureDataType struct =
				new StructureDataType(new CategoryPath(PATH), "SmallExceptionHandlerClause", 0);
			struct.add(WORD, "Flags", "COR_ILEXCEPTION_CLAUSE_*"); //  TODO: explain flags
			struct.add(WORD, "TryOffset", "Offset in bytes of try block from start of header");
			struct.add(BYTE, "TryLength", "Length in bytes of try block");
			struct.add(WORD, "HandlerOffset", "Location of handler for this try block");
			struct.add(BYTE, "HandlerLength", "Size of handler code in bytes");
			if (isFilterBasedException) {
				struct.add(DWORD, "FilterOffset",
					"Offset in method body for filter-based exception handler");
			}
			else {
				struct.add(DWORD, "ClassToken", "Metadata token for type-based exception handler");
			}
			return struct;
		}

		public StructureDataType getFatExceptionClauseDataType() {
			StructureDataType struct =
				new StructureDataType(new CategoryPath(PATH), "FatExceptionHandlerClause", 0);
			struct.add(DWORD, "Flags", "COR_ILEXCEPTION_CLAUSE_*"); //  TODO: explain flags
			struct.add(DWORD, "TryOffset", "Offset in bytes of try block from start of header");
			struct.add(DWORD, "TryLength", "Length in bytes of try block");
			struct.add(DWORD, "HandlerOffset", "Location of handler for this try block");
			struct.add(DWORD, "HandlerLength", "Size of handler code in bytes");
			if (isFilterBasedException) {
				struct.add(DWORD, "FilterOffset",
					"Offset in method body for filter-based exception handler");
			}
			else {
				struct.add(DWORD, "ClassToken", "Metadata token for type-based exception handler");
			}
			return struct;
		}

		public DataType toDataType() {
			// Default to skinny clause size
			int clauseSize = 12;
			if (isFat) {
				clauseSize = 24;
			}

			int numberClauses = (dataSize - 4) / clauseSize;
			StructureDataType struct =
				new StructureDataType(new CategoryPath(PATH), "ExtraSection", 0);
			struct.add(BYTE, "Kind", "flags: EH, OptIL, FatFormat, MoreSects"); // TODO: explain flags
			if (isFat) {
				struct.add(BYTE, "size byte 1", "first byte");
				struct.add(WORD, "size bytes 2-3", "size continued. n*24+4 clauses follow.");
				struct.add(
					new ArrayDataType(getFatExceptionClauseDataType(), numberClauses, clauseSize),
					"Clauses", null);
			}
			else {
				struct.add(BYTE, "DataSize", "section size inc. header; n*12+4 clauses follow");
				struct.add(WORD, "Padding", "always 0");
				struct.add(
					new ArrayDataType(getSmallExceptionClauseDataType(), numberClauses, clauseSize),
					"Clauses", null);
			}
			return struct;
		}
	}

	public CliMethodExtraSections(BinaryReader reader) throws IOException {
		ExtraSection section;
		do {
			section = new ExtraSection(reader);
			extraSections.add(section);
		}
		while (section.hasMoreSections);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct =
			new StructureDataType(new CategoryPath(PATH), "ExtraSections", 0);
		for (ExtraSection section : extraSections) {
			struct.add(section.toDataType(), "ExtraSection", null);
		}
		return struct;
	}

}
