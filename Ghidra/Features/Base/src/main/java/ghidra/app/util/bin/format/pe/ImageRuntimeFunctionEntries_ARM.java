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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;

/**
 * <pre>
 * typedef struct _IMAGE_ARM_RUNTIME_FUNCTION_ENTRY {
 *   DWORD BeginAddress;
 *   union {
 *     DWORD UnwindData;
 *     struct {
 *       DWORD Flag : 2;
 *       DWORD FunctionLength : 11;
 *       DWORD Ret : 2;
 *       DWORD H : 1;
 *       DWORD Reg : 3;
 *       DWORD R : 1;
 *       DWORD L : 1;
 *       DWORD C : 1;
 *       DWORD StackAdjust : 10;
 *     } DUMMYSTRUCTNAME;
 *   } DUMMYUNIONNAME;
 * } IMAGE_ARM_RUNTIME_FUNCTION_ENTRY, * PIMAGE_ARM_RUNTIME_FUNCTION_ENTRY;
 * </pre>
 * @see <a href="https://github.com/MicrosoftDocs/cpp-docs/blob/main/docs/build/arm-exception-handling.md">arm-exception-handling.md</a> 
 */
public class ImageRuntimeFunctionEntries_ARM implements ImageRuntimeFunctionEntries {

	private final static int ENTRY_SIZE = 0x08;

	private List<ImageRuntimeFunctionEntry_ARM> functionEntries = new ArrayList<>();

	/**
	 * Creates a new {@link ImageRuntimeFunctionEntries_X86}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the exception data directory
	 * @param size The size of the exception data directory
	 * @param ntHeader The {@link NTHeader}
	 * @throws IOException If there was an issue parsing the exception data directory
	 */
	ImageRuntimeFunctionEntries_ARM(BinaryReader reader, int size, NTHeader ntHeader)
			throws IOException {
		int numEntries = size / ENTRY_SIZE;
		for (int i = 0; i < numEntries; i++) {
			long beginAddress = reader.readNextUnsignedInt() & ~0x1L; // low bit is set when thumb
			int data = reader.readNextInt();
			if (beginAddress == 0 && data == 0) {
				break;
			}

			functionEntries.add(new ImageRuntimeFunctionEntry_ARM(beginAddress, data));
		}
	}

	@Override
	public void markup(Program program, Address headerStart) throws CodeUnitInsertionException,
			IOException, DuplicateNameException {
		StructureDataType exceptionInfoStruct = new StructureDataType("_IMAGE_RUNTIME_FUNCTION_ENTRY", 0);
		exceptionInfoStruct.setPackingEnabled(true);
		exceptionInfoStruct.add(StructConverter.IBO32, "BeginAddress", null);
		exceptionInfoStruct.add(StructConverter.IBO32, "ExceptionInfo", null);

		StructureDataType unwindDataStruct = new StructureDataType("_IMAGE_RUNTIME_FUNCTION_ENTRY_2", 0);
		unwindDataStruct.setPackingEnabled(true);
		unwindDataStruct.add(StructConverter.IBO32, "BeginAddress", null);
		try {
			unwindDataStruct.addBitField(StructConverter.DWORD, 2, "Flag", null);
			unwindDataStruct.addBitField(StructConverter.DWORD, 11, "FunctionLength", null);
			unwindDataStruct.addBitField(StructConverter.DWORD, 2, "Ret", null);
			unwindDataStruct.addBitField(StructConverter.DWORD, 1, "H", null);
			unwindDataStruct.addBitField(StructConverter.DWORD, 3, "Reg", null);
			unwindDataStruct.addBitField(StructConverter.DWORD, 1, "R", null);
			unwindDataStruct.addBitField(StructConverter.DWORD, 1, "L", null);
			unwindDataStruct.addBitField(StructConverter.DWORD, 1, "C", null);
			unwindDataStruct.addBitField(StructConverter.DWORD, 10, "StackAdjust", null);
		}
		catch (InvalidDataTypeException e) {
			throw new IOException(e);
		}

		Address addr = headerStart;
		for (ImageRuntimeFunctionEntry_ARM entry : functionEntries) {
			DataType struct = entry.isExceptionInfoRVA() ? exceptionInfoStruct : unwindDataStruct;
			DataUtilities.createData(program, addr, struct, struct.getLength(), true,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
			addr = addr.add(ENTRY_SIZE);
		}
	}

	/**
	 * Creates a new {@link ImageRuntimeFunctionEntries_ARM}
	 * 
	 * @param beginAddress The RVA of the corresponding function
	 * @param data The exception info RVA or the packed unwind data, depending on lower 2 bit flag
	 */
	record ImageRuntimeFunctionEntry_ARM(long beginAddress, int data) {
		
		/**
		 * Checks whether or not this entry is an exception info RVA or packed unwind data
		 * 
		 * @return True if this entry is an exception info RVA, or false if it's packed unwind data
		 */
		public boolean isExceptionInfoRVA() {
			return (data & 0x3) == 0;
		}
		
		/**
		 * Marks up this entry
		 * 
		 * @param program The {@link Program}
		 * @throws IOException If there was an IO-related error creating the data
		 * @throws DuplicateNameException If a data type of the same name already exists
		 * @throws CodeUnitInsertionException If data creation failed
		 */
		public void markup(Program program)
				throws DuplicateNameException, IOException, CodeUnitInsertionException {
			if (isExceptionInfoRVA()) {
				// TODO
			}
		}
	}
}
