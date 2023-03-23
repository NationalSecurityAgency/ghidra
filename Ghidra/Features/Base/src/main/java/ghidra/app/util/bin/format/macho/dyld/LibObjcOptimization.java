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
package ghidra.app.util.bin.format.macho.dyld;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Represents a objc_opt_t structure, which resides in the libobjc DYLIB within a DYLD cache
 * 
 * @see <a href="https://github.com/apple-oss-distributions/dyld/blob/main/include/objc-shared-cache.h">dyld/include/objc-shared-cache.h</a> 
 */
@SuppressWarnings("unused")
public class LibObjcOptimization implements StructConverter {

	/**
	 * The name of the section that contains the objc_opt_t_structure
	 */
	public final static String SECTION_NAME = "__objc_opt_ro";

	private int version;
	private int flags;
	private int selopt_offset;
	private int headeropt_ro_offset;
	private int clsopt_offset;
	private int protocolopt1_offset;
	private int headeropt_rw_offset;
	private int protocolopt2_offset;
	private int largeSharedCachesClassOffset;
	private int largeSharedCachesProtocolOffset;
	private long relativeMethodSelectorBaseAddressOffset;

	private long objcOptAddr;

	/**
	 * Create a new {@link LibObjcOptimization}.
	 * 
	 * @param program The {@link Program}
	 * @param objcOptRoSectionAddr The start address of the __objc_opt_ro section
	 * @throws IOException if there was an IO-related problem parsing the structure
	 */
	public LibObjcOptimization(Program program, Address objcOptRoSectionAddr) throws IOException {
		try (ByteProvider provider =
			new MemoryByteProvider(program.getMemory(), objcOptRoSectionAddr)) {
			BinaryReader reader = new BinaryReader(provider, !program.getLanguage().isBigEndian());

			version = reader.readNextInt();
			if (version <= 14) {
				selopt_offset = reader.readNextInt();
				headeropt_ro_offset = reader.readNextInt();
				clsopt_offset = reader.readNextInt();
				if (version >= 13) {
					protocolopt1_offset = reader.readNextInt();
				}
			}
			else {
				flags = reader.readNextInt();
				selopt_offset = reader.readNextInt();
				headeropt_ro_offset = reader.readNextInt();
				clsopt_offset = reader.readNextInt();
				protocolopt1_offset = reader.readNextInt();
				headeropt_rw_offset = reader.readNextInt();
				protocolopt2_offset = reader.readNextInt();
				if (version >= 16) {
					largeSharedCachesClassOffset = reader.readNextInt();
					largeSharedCachesProtocolOffset = reader.readNextInt();
					relativeMethodSelectorBaseAddressOffset = reader.readNextLong();
				}
			}
		}

		objcOptAddr = objcOptRoSectionAddr.getOffset();
	}

	/**
	 * Gets the address of the objc_opt_t structure
	 * 
	 * @return The address of the objc_opt_t structure
	 */
	public long getAddr() {
		return objcOptAddr;
	}

	/**
	 * Gets the relative method selector base address offset.  This will be 0 if the version is less
	 * than 16.
	 * 
	 * @return The relative method selector base address offset
	 */
	public long getRelativeSelectorBaseAddressOffset() {
		return relativeMethodSelectorBaseAddressOffset;
	}

	/**
	 * Marks up up this structure in memory
	 * 
	 * @param program The {@link Program}
	 * @param space The {@link AddressSpace}
	 * @param log The log
	 * @param monitor A cancelable task monitor
	 */
	public void markup(Program program, AddressSpace space, MessageLog log, TaskMonitor monitor) {
		Address addr = space.getAddress(getAddr());
		try {
			DataUtilities.createData(program, addr, toDataType(), -1,
				DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
		}
		catch (CodeUnitInsertionException | DuplicateNameException | IOException e) {
			log.appendMsg(LibObjcOptimization.class.getSimpleName(),
				"Failed to markup objc_opt_t.");
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType("objc_opt_t", 0);
		if (version <= 12) {
			struct.add(DWORD, "version", "");
			struct.add(DWORD, "selopt_offset", "");
			struct.add(DWORD, "headeropt_offset", "");
			struct.add(DWORD, "clsopt_offset", "");
		}
		else if (version >= 13 && version <= 14) {
			struct.add(DWORD, "version", "");
			struct.add(DWORD, "selopt_offset", "");
			struct.add(DWORD, "headeropt_offset", "");
			struct.add(DWORD, "clsopt_offset", "");
			struct.add(DWORD, "protocolopt_offset", "");
		}
		else if (version == 15) {
			struct.add(DWORD, "version", "");
			struct.add(DWORD, "flags", "");
			struct.add(DWORD, "selopt_offset", "");
			struct.add(DWORD, "headeropt_ro_offset", "");
			struct.add(DWORD, "clsopt_offset", "");
			struct.add(DWORD, "unused_protocolopt_offset", "");
			struct.add(DWORD, "headeropt_rw_offset", "");
			struct.add(DWORD, "protocolopt_offset", "");
		}
		else { // version >= 16
			struct.add(DWORD, "version", "");
			struct.add(DWORD, "flags", "");
			struct.add(DWORD, "selopt_offset", "");
			struct.add(DWORD, "headeropt_ro_offset", "");
			struct.add(DWORD, "unused_clsopt_offset", "");
			struct.add(DWORD, "unused_protocolopt_offset", "");
			struct.add(DWORD, "headeropt_rw_offset", "");
			struct.add(DWORD, "unused_protocolopt2_offset", "");
			struct.add(DWORD, "largeSharedCachesClassOffset", "");
			struct.add(DWORD, "largeSharedCachesProtocolOffset", "");
			struct.add(QWORD, "relativeMethodSelectorBaseAddressOffset", "");

		}
		return struct;
	}
}
