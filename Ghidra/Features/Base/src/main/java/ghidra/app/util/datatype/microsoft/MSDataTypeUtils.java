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
package ghidra.app.util.datatype.microsoft;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.datamgr.archive.DuplicateIdException;
import ghidra.app.plugin.core.datamgr.util.DataTypeArchiveUtility;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;

/**
 * An abstract class containing static utility methods for creating structure data types.
 */
public class MSDataTypeUtils {

	private MSDataTypeUtils() {
		// utility class; can't create
	}

	/**
	 * Determines if the indicated program appears to be 64 bit (has 64 bit pointers).
	 * @param program the program
	 * @return true if 64 bit.
	 */
	public static boolean is64Bit(Program program) {
		return program.getDefaultPointerSize() == 8;
	}

	/**
	 * Gets an empty aligned structure with a packing value of 8 that can be use to create the 
	 * model's data type.
	 * @param dataTypeManager the data type manager to associate with the structure.
	 * @param categoryPath the structure's category path.
	 * @param structureName the structure's name.
	 * @return the aligned pack(8) structure.
	 */
	public static StructureDataType getAlignedPack8Structure(DataTypeManager dataTypeManager,
			CategoryPath categoryPath, String structureName) {
		return getAlignedPackedStructure(dataTypeManager, categoryPath, structureName, 8);
	}

	/**
	 * Gets an empty aligned structure with a packing value of 4 that can be use to create the 
	 * model's data type.
	 * @param dataTypeManager the data type manager to associate with the structure.
	 * @param categoryPath the structure's category path.
	 * @param structureName the structure's name.
	 * @return the aligned pack(4) structure.
	 */
	public static StructureDataType getAlignedPack4Structure(DataTypeManager dataTypeManager,
			CategoryPath categoryPath, String structureName) {
		return getAlignedPackedStructure(dataTypeManager, categoryPath, structureName, 4);
	}

	/**
	 * Gets an empty aligned structure with the indicated packing value that can be use to create the 
	 * model's data type.
	 * @param dataTypeManager the data type manager to associate with the structure.
	 * @param categoryPath the structure's category path.
	 * @param structureName the structure's name.
	 * @param packValue the packing value or 0 NOT_PACKING
	 * @return the aligned packed structure.
	 */
	private static StructureDataType getAlignedPackedStructure(DataTypeManager dataTypeManager,
			CategoryPath categoryPath, String structureName, int packValue) {
		StructureDataType struct =
			new StructureDataType(categoryPath, structureName, 0, dataTypeManager);
		struct.setPackingEnabled(true);
		if (packValue > 0) {
			struct.setExplicitPackingValue(packValue);
		}
		return struct;
	}

	/**
	 * Gets an exception handling state data type.
	 * @param program the program for the data type.
	 * @return the exception handling state data type.
	 */
	public static DataType getEHStateDataType(Program program) {

		DataTypeManager dtm = program.getDataTypeManager();
		DataType dt = new TypedefDataType(new CategoryPath("/"), "__ehstate_t",
			new IntegerDataType(dtm), dtm);
		return MSDataTypeUtils.getMatchingDataType(program, dt);
	}

	/**
	 * Gets a pointer displacement data type.
	 * @param program the program for the data type.
	 * @return the pointer displacement data type.
	 */
	public static DataType getPointerDisplacementDataType(Program program) {

		DataTypeManager dtm = program.getDataTypeManager();
		DataType dt =
			new TypedefDataType(new CategoryPath("/"), "ptrdiff_t", new IntegerDataType(dtm), dtm);
		return MSDataTypeUtils.getMatchingDataType(program, dt);
	}

	/**
	 * Gets a PMD displacement structure data type.
	 * @param program the program for the data type.
	 * @return the PMD data type or null.
	 */
	public static Structure getPMDDataType(Program program) {

		DataTypeManager dtm = program.getDataTypeManager();
		DataType dt = is64Bit(program) ? new IntegerDataType(dtm)
				: MSDataTypeUtils.getPointerDisplacementDataType(program);
		StructureDataType struct =
			MSDataTypeUtils.getAlignedPack4Structure(dtm, new CategoryPath("/"), "PMD");
		struct.add(dt, 4, "mdisp", null);
		struct.add(dt, 4, "pdisp", null);
		struct.add(dt, 4, "vdisp", null);

		return (Structure) MSDataTypeUtils.getMatchingDataType(program, struct);
	}

	private static DataTypeManager getWinDTM(Program program)
			throws IOException, DuplicateIdException {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		DataTypeManagerService service = mgr.getDataTypeManagerService();
		List<String> archiveList = DataTypeArchiveUtility.getArchiveList(program);
		for (String archiveName : archiveList) {
			if (archiveName.startsWith("windows_vs")) {
				return service.openDataTypeArchive(archiveName);
			}
		}
		return null;
	}

	/**
	 * Gets the named data type from the program or the windows data type archive. If neither 
	 * the program or data type archive has an equivalent data type then the original data type 
	 * is returned.
	 * @param program the program for the data type.
	 * @param comparisonDt the data type it should match
	 * @return the matching data type
	 */
	public static DataType getMatchingDataType(Program program, DataType comparisonDt) {

		DataTypeManager programDTM = program.getDataTypeManager();
		DataType matchingDt = findMatchingDataType(comparisonDt, programDTM);
		if (matchingDt == null) {
			try {
				DataTypeManager winDTM = getWinDTM(program);
				if (winDTM != null) {
					matchingDt = findMatchingDataType(comparisonDt, winDTM);
				}
			}
			catch (IOException | DuplicateIdException e) {
				// Can't get data type archive so just do nothing.
			}
		}
		return (matchingDt != null) ? matchingDt : comparisonDt;
	}

	private static DataType findMatchingDataType(DataType comparisonDt,
			DataTypeManager programDTM) {

		// Try to get data type with same full path name.
		DataType oldDataType =
			programDTM.getDataType(comparisonDt.getCategoryPath(), comparisonDt.getName());
		if (oldDataType != null) {
			return oldDataType;
		}

		String name = comparisonDt.getName();
		List<DataType> dataTypes = new ArrayList<>();
		programDTM.findDataTypes(name, dataTypes);
		for (DataType dataType : dataTypes) {
			if (dataType.getLength() != comparisonDt.getLength()) {
				continue;
			}
			// For now this uses the DataType.isEquivalent() method for comparing the 
			// data types. However, the method is still rather rigid. It would be better 
			// if there was another method that were more lenient. The hard part is 
			// determining what types of differences should be deemed equivalent.
			if (dataType.isEquivalent(comparisonDt)) {
				return dataType; // Return the first one we find that matches.
			}
		}
		return null;
	}

	/**
	 * Extracts an absolute address from the bytes in memory at the indicated address in memory.
	 * @param program the program containing the bytes
	 * @param address the address in memory where the address bytes should be obtained.
	 * @return the absolute address or null if the address isn't in the program's memory.
	 */
	public static Address getAbsoluteAddress(Program program, Address address) {
		DataType refDt = new PointerDataType(program.getDataTypeManager());
		DumbMemBufferImpl compMemBuffer = new DumbMemBufferImpl(program.getMemory(), address);
		return (Address) refDt.getValue(compMemBuffer, refDt.getDefaultSettings(), -1);
	}

	/**
	 * Gets the referred to address from the bytes in the program at the indicated address.
	 * If the program has 64 bit pointers, then a 32 bit image base offset value is expected to 
	 * be found at the indicated address. 
	 * If the program has 32 bit pointers, then a 32 bit absolute pointer value is expected at the
	 * indicated address.
	 * @param program the program whose memory is to be read.
	 * @param address the address to start reading the bytes for the referenced address.
	 * @return the referred to address or null.
	 */
	public static Address getReferencedAddress(Program program, Address address) {
		DataType refDt = getReferenceDataType(program, null);
		int length = refDt.getLength();
		DumbMemBufferImpl compMemBuffer = new DumbMemBufferImpl(program.getMemory(), address);
		Object value = refDt.getValue(compMemBuffer, refDt.getDefaultSettings(), length);
		return (value instanceof Address) ? (Address) value : null;
	}

	/**
	 * Gets bytes from <code>memory</code> at the indicated <code>startAddress</code>. 
	 * The <code>length</code> indicates the number of bytes that must be read 
	 * from memory.
	 * @param memory the program memory for obtaining the bytes
	 * @param startAddress the address to begin reading bytes
	 * @param length the number of bytes to read
	 * @return the bytes
	 * @throws InvalidDataTypeException if the <code>length</code> number of bytes couldn't 
	 * be read starting at the <code>startAddress</code> in <code>memory</code>.
	 */
	public static byte[] getBytes(Memory memory, Address startAddress, int length)
			throws InvalidDataTypeException {
		byte[] bytes = new byte[length];
		try {
			int bytesRead = memory.getBytes(startAddress, bytes);
			if (bytesRead != length) { // Don't have enough bytes.
				throw new InvalidDataTypeException(
					"Only read " + bytesRead + " bytes when trying to read " + length + "."); // throws Exception
			}
		}
		catch (MemoryAccessException e) {
			String message = "Couldn't read " + length + " bytes at " + startAddress + ".";
			throw new InvalidDataTypeException(message, e); // throws Exception
		}
		return bytes; // Only get here if getBytes() succeeds.
	}

	/**
	 * Gets the appropriate reference data type. If program is 64 bit, then a 32-bit image 
	 * base offset data type will be returned. Otherwise, a default pointer to the 
	 * referredToDataType will be returned.
	 * @param program the program that will contain the returned data type
	 * @param referredToDataType the data type that is at the address being referred to by the 
	 * pointer or image base offset. Otherwise, null.
	 * @return the image base offset or pointer reference data type
	 */
	public static DataType getReferenceDataType(Program program, DataType referredToDataType) {
		DataTypeManager dtm = program.getDataTypeManager();
		return is64Bit(program) ? new ImageBaseOffset32DataType(dtm)
				: new PointerDataType(referredToDataType);
	}
}
