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
 * typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY {
 *  DWORD BeginAddress;
 *  DWORD EndAddress;
 *  union {
 *    DWORD UnwindInfoAddress;
 *    DWORD UnwindData;
 *  } DUMMYUNIONNAME;
 * } RUNTIME_FUNCTION, *PRUNTIME_FUNCTION, _IMAGE_RUNTIME_FUNCTION_ENTRY, *_PIMAGE_RUNTIME_FUNCTION_ENTRY;
 *
 * #define UNW_FLAG_NHANDLER 0x0
 * #define UNW_FLAG_EHANDLER 0x1
 * #define UNW_FLAG_UHANDLER 0x2
 * #define UNW_FLAG_CHAININFO 0x4
 *
 * typedef struct _UNWIND_INFO {
 *     UCHAR Version : 3;
 *     UCHAR Flags : 5;
 *     UCHAR SizeOfProlog;
 *     UCHAR CountOfUnwindCodes;
 *     UCHAR FrameRegister : 4;
 *     UCHAR FrameOffset : 4;
 *     UNWIND_CODE UnwindCode[1];
 *
 * //
 * // The unwind codes are followed by an optional DWORD aligned field that
 * // contains the exception handler address or the address of chained unwind
 * // information. If an exception handler address is specified, then it is
 * // followed by the language specified exception handler data.
 * //
 * //  union {
 * //      ULONG ExceptionHandler;
 * //      ULONG FunctionEntry;
 * //  };
 * //
 * //  ULONG ExceptionData[];
 * //
 * } UNWIND_INFO, *PUNWIND_INFO;
 * </pre>
 */
public class ImageRuntimeFunctionEntries_X86 implements ImageRuntimeFunctionEntries {

	private final static int ENTRY_SIZE = 0x0C;

	private List<ImageRuntimeFunctionEntry_X86> functionEntries = new ArrayList<>();

	/**
	 * Creates a new {@link ImageRuntimeFunctionEntries_X86}
	 * 
	 * @param reader A {@link BinaryReader} positioned at the start of the exception data directory
	 * @param size The size of the exception data directory
	 * @param ntHeader The {@link NTHeader}
	 * @throws IOException If there was an issue parsing the exception data directory
	 */
	ImageRuntimeFunctionEntries_X86(BinaryReader reader, int size, NTHeader ntHeader)
			throws IOException {

		int numEntries = size / ENTRY_SIZE;
		for (int i = 0; i < numEntries; i++) {
			long beginAddress = reader.readNextUnsignedInt();
			long endAddress = reader.readNextUnsignedInt();
			long unwindInfoAddressOrData = reader.readNextUnsignedInt();

			if (beginAddress == 0 && endAddress == 0 && unwindInfoAddressOrData == 0) {
				break;
			}

			PEx64UnwindInfo unwindInfo =
				PEx64UnwindInfo.readUnwindInfo(reader, unwindInfoAddressOrData, ntHeader);

			ImageRuntimeFunctionEntry_X86 entry = new ImageRuntimeFunctionEntry_X86(beginAddress,
				endAddress, unwindInfoAddressOrData, unwindInfo);
			functionEntries.add(entry);
		}
	}

	@Override
	public void markup(Program program, Address headerStart) throws CodeUnitInsertionException,
			IOException, DuplicateNameException {
		StructureDataType struct = new StructureDataType("_IMAGE_RUNTIME_FUNCTION_ENTRY", 0);
		struct.add(StructConverter.IBO32, "BeginAddress", null);
		struct.add(StructConverter.IBO32, "EndAddress", null);
		struct.add(StructConverter.IBO32, "UnwindInfoAddressOrData", null);

		ArrayDataType arr = new ArrayDataType(struct, functionEntries.size(), struct.getLength());

		DataUtilities.createData(program, headerStart, arr, arr.getLength(), true,
			DataUtilities.ClearDataMode.CHECK_FOR_SPACE);

		for (ImageRuntimeFunctionEntry_X86 entry : functionEntries) {
			entry.markup(program);
		}
	}

	/**
	 * Creates a new {@link ImageRuntimeFunctionEntries_X86}
	 * 
	 * @param beginAddress The RVA of the corresponding function
	 * @param endAddress The RVA of the end of the function
	 * @param unwindInfoAddressOrData The RVA of the unwind information
	 * @param unwindInfo The parsed {@link PEx64UnwindInfo unwind information}
	 */
	record ImageRuntimeFunctionEntry_X86(long beginAddress, long endAddress,
			long unwindInfoAddressOrData, PEx64UnwindInfo unwindInfo) {

		/**
		 * Marks up this entry
		 * 
		 * @param program The {@link Program}
		 * @throws IOException If there was an IO-related error creating the data
		 * @throws DuplicateNameException If a data type of the same name already exists
		 */
		public void markup(Program program) throws DuplicateNameException, IOException {
			if (unwindInfoAddressOrData > 0) {
				DataType dt = unwindInfo.toDataType();
				Address start = program.getImageBase().add(unwindInfoAddressOrData);

				try {
					DataUtilities.createData(program, start, dt, dt.getLength(), true,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				catch (CodeUnitInsertionException e) {
					// expected...ignore
				}
			}
		}
	}
}
