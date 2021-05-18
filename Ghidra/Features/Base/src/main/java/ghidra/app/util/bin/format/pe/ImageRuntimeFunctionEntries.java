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

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;

/**
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
 */
public class ImageRuntimeFunctionEntries {

	private final static int UNWIND_INFO_SIZE = 0x0C;

	List<_IMAGE_RUNTIME_FUNCTION_ENTRY> functionEntries = new ArrayList<>();

	static ImageRuntimeFunctionEntries createImageRuntimeFunctionEntries(
			FactoryBundledWithBinaryReader reader, long index, NTHeader ntHeader)
			throws IOException {
		ImageRuntimeFunctionEntries imageRuntimeFunctionEntriesSection =
			(ImageRuntimeFunctionEntries) reader.getFactory()
					.create(ImageRuntimeFunctionEntries.class);
		imageRuntimeFunctionEntriesSection.initImageRuntimeFunctionEntries(reader, index, ntHeader);
		return imageRuntimeFunctionEntriesSection;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ImageRuntimeFunctionEntries() {
	}

	private void initImageRuntimeFunctionEntries(FactoryBundledWithBinaryReader reader, long index,
			NTHeader ntHeader) throws IOException {

		int entryCount = 0;

		// Find the exception handler data section. This is an unbounded array of
		// RUNTIME_INFO structures one after another and there's no count field
		// to tell us how many there are, so get the maximum number there could be
		// based on the size of the section.
		FileHeader fh = ntHeader.getFileHeader();
		for (SectionHeader section : fh.getSectionHeaders()) {
			if (section.getName().contentEquals(".pdata")) {
				entryCount = section.getSizeOfRawData() / UNWIND_INFO_SIZE;
				break;
			}
		}

		if (entryCount == 0) {
			return;
		}

		long origIndex = reader.getPointerIndex();

		reader.setPointerIndex(index);

		for (int i = 0; i < entryCount; i++) {
			_IMAGE_RUNTIME_FUNCTION_ENTRY entry = new _IMAGE_RUNTIME_FUNCTION_ENTRY();
			entry.beginAddress = reader.readNextUnsignedInt();
			entry.endAddress = reader.readNextUnsignedInt();
			entry.unwindInfoAddressOrData = reader.readNextUnsignedInt();

			// When the size of the section is bigger than the number of structures
			// the structure data fields will all be null, signaling the end of the
			// array of structures. Break out here.
			if (entry.beginAddress == 0 && entry.endAddress == 0 &&
				entry.unwindInfoAddressOrData == 0) {
				break;
			}

			// Read and process the UNWIND_INFO structures the RUNTIME_INFO
			// structures point to
			entry.unwindInfo =
				PEx64UnwindInfo.readUnwindInfo(reader, entry.unwindInfoAddressOrData, ntHeader);

			functionEntries.add(entry);
		}

		reader.setPointerIndex(origIndex);
	}

	public List<_IMAGE_RUNTIME_FUNCTION_ENTRY> getRuntimeFunctionEntries() {
		return functionEntries;
	}

	public static void createData(Program program, Address headerStart,
			List<_IMAGE_RUNTIME_FUNCTION_ENTRY> irfes) {
		// TODO: This is x86-64 architecture-specific and needs to be generalized.
		StructureDataType dt = new StructureDataType(".PDATA", 0);
		dt.setCategoryPath(new CategoryPath("/PE"));

		// Lay an array of RUNTIME_INFO structure out over the data
		StructureDataType irfeStruct = new StructureDataType("_IMAGE_RUNTIME_FUNCTION_ENTRY", 0);
		irfeStruct.add(ghidra.app.util.bin.StructConverter.IBO32, "BeginAddress", null);
		irfeStruct.add(ghidra.app.util.bin.StructConverter.IBO32, "EndAddress", null);
		irfeStruct.add(ghidra.app.util.bin.StructConverter.IBO32, "UnwindInfoAddressOrData", null);

		ArrayDataType irfeArray =
			new ArrayDataType(irfeStruct, irfes.size(), irfeStruct.getLength());

		try {
			DataUtilities.createData(program, headerStart, irfeArray, irfeArray.getLength(), true,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
		}
		catch (CodeUnitInsertionException e) {
			return;
		}
	}

	// FIXME: change name to conform to Java naming standards
	// FIXME: If public visibility is required improved member protection is needed
	public static class _IMAGE_RUNTIME_FUNCTION_ENTRY {
		long beginAddress;
		long endAddress;
		long unwindInfoAddressOrData;
		PEx64UnwindInfo unwindInfo;

		public void createData(Program program) {
			if (unwindInfoAddressOrData > 0) {
				try {
					DataType dt = unwindInfo.toDataType();
					Address start = program.getImageBase().add(unwindInfoAddressOrData);

					DataUtilities.createData(program, start, dt, dt.getLength(), true,
						DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
				}
				catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
					// ignore
				}
			}
		}
	}

}
