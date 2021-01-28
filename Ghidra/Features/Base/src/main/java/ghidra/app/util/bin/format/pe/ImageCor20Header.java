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

import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.cli.CliMetadataDirectory;
import ghidra.app.util.bin.format.pe.cli.streams.CliStreamMetadata;
import ghidra.app.util.bin.format.pe.cli.tables.CliTableMethodDef.CliMethodDefRow;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * typedef struct IMAGE_COR20_HEADER
 * {
 *     // Header versioning
 *    DWORD                   cb;                      // Size of the structure
 *    WORD                    MajorRuntimeVersion;     // Version of the CLR Runtime
 *    WORD                    MinorRuntimeVersion;     // Version of the CLR Runtime
 *
 *    // Symbol table and startup information
 *    IMAGE_DATA_DIRECTORY    MetaData;                // A Data Directory giving RVA and Size of MetaData
 *    DWORD                   Flags;
 *    union {
 *      DWORD                 EntryPointRVA;           // Points to the .NET native EntryPoint method
 *      DWORD                 EntryPointToken;         // Points to the .NET IL EntryPoint method
 *    };
 *
 *    // Binding information
 *    IMAGE_DATA_DIRECTORY    Resources;               // A Data Directory for Resources, which are referenced in the MetaData
 *    IMAGE_DATA_DIRECTORY    StrongNameSignature;     // A Data Directory for unique .NET assembly signatures
 *
 *    // Regular fixup and binding information
 *    IMAGE_DATA_DIRECTORY    CodeManagerTable;        // Always 0
 *    IMAGE_DATA_DIRECTORY    VTableFixups;            // Not well documented VTable used by languages who don't follow the common type system runtime model
 *    IMAGE_DATA_DIRECTORY    ExportAddressTableJumps; // Always 0 in normal .NET assemblies, only present in native images
 *
 *    // Precompiled image info (internal use only - set to zero)
 *    IMAGE_DATA_DIRECTORY    ManagedNativeHeader;
 *
 *};
 *</pre>
 *
 */
public class ImageCor20Header implements StructConverter, PeMarkupable {
	private static final String NAME = "IMAGE_COR20_HEADER";

	private int cb;
	private short majorRuntimeVersion;
	private short minorRuntimeVersion;
	private CliMetadataDirectory metadata;
	private int flags;
	private int entryPointToken;
	private Address entryPointVA;
	private DefaultDataDirectory resources;
	private DefaultDataDirectory strongNameSignature;
	private DefaultDataDirectory codeManagerTable;
	private DefaultDataDirectory vTableFixups;
	private DefaultDataDirectory exportAddressTableJumps;
	private DefaultDataDirectory managedNativeHeader;

	static ImageCor20Header createImageCor20Header(FactoryBundledWithBinaryReader reader,
			long index, NTHeader ntHeader) throws IOException {
		ImageCor20Header imageCor20Header =
			(ImageCor20Header) reader.getFactory().create(ImageCor20Header.class);
		imageCor20Header.initIMAGE_COR20_HEADER(reader, index, ntHeader);
		return imageCor20Header;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ImageCor20Header() {
	}

	private void initIMAGE_COR20_HEADER(FactoryBundledWithBinaryReader reader, long index,
			NTHeader ntHeader) throws IOException {
		long origIndex = reader.getPointerIndex();

		reader.setPointerIndex(index);

		cb = reader.readNextInt();
		majorRuntimeVersion = reader.readNextShort();
		minorRuntimeVersion = reader.readNextShort();
		metadata = CliMetadataDirectory.createCliMetadataDirectory(ntHeader, reader);
		flags = reader.readNextInt();
		entryPointToken = reader.readNextInt();
		resources = DefaultDataDirectory.createDefaultDataDirectory(ntHeader, reader);
		strongNameSignature = DefaultDataDirectory.createDefaultDataDirectory(ntHeader, reader);
		codeManagerTable = DefaultDataDirectory.createDefaultDataDirectory(ntHeader, reader);
		vTableFixups = DefaultDataDirectory.createDefaultDataDirectory(ntHeader, reader);
		exportAddressTableJumps = DefaultDataDirectory.createDefaultDataDirectory(ntHeader, reader);
		managedNativeHeader = DefaultDataDirectory.createDefaultDataDirectory(ntHeader, reader);

		reader.setPointerIndex(origIndex);
	}

	/**
	 * Parses this header
	 *
	 * @return True if parsing completed successfully; otherwise, false.
	 * @throws IOException If there was an IO problem while parsing.
	 */
	public boolean parse() throws IOException {
		boolean success = true;

		success &= metadata.parse();
		success &= resources.parse();
		success &= strongNameSignature.parse();
		success &= codeManagerTable.parse();
		success &= vTableFixups.parse();
		success &= exportAddressTableJumps.parse();
		success &= managedNativeHeader.parse();

		return success;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			IOException, MemoryAccessException {

		if (!metadata.hasParsedCorrectly()) {
			return;
		}

		metadata.markup(program, isBinary, monitor, log, ntHeader);

		if (entryPointToken > 0) { // DLL's won't have an entry point
			try {
				if ((flags &
					ImageCor20Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) == ImageCor20Flags.COMIMAGE_FLAGS_NATIVE_ENTRYPOINT) {
					// Add new symbol for the native entry point
					program.getSymbolTable()
							.addExternalEntryPoint(program.getImageBase().add(entryPointToken));
				}
				else {
					// Add a new symbol for the .NET entry point
					CliStreamMetadata stream = (CliStreamMetadata) metadata.getMetadataRoot()
							.getStreamHeader(CliStreamMetadata.getName())
							.getStream();

					CliMethodDefRow row =
						(CliMethodDefRow) stream.getTable((entryPointToken & 0xff000000) >> 24)
								.getRow(entryPointToken & 0x00ffffff);

					program.getSymbolTable()
							.addExternalEntryPoint(program.getImageBase().add(row.RVA));

					entryPointVA = program.getImageBase().add(row.RVA);
				}
			}
			catch (Exception e) {
				log.appendException(e);
			}
		}
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		StructureDataType struct = new StructureDataType(NAME, 0);
		struct.add(new DWordDataType(), "cb", "Size of the structure");
		struct.add(new WordDataType(), "MajorRuntimeVersion", "Version of CLR Runtime");
		struct.add(new WordDataType(), "MinorRuntimeVersion", null);
		struct.add(metadata.toDataType(), "MetaData", "RVA and size of MetaData");
		struct.add(new ImageCor20Flags(), "Flags", null);
		struct.add(new DWordDataType(), "EntryPointToken",
			"This is a metadata token if not a valid RVA");
		struct.add(resources.toDataType(), "Resources", null);
		struct.add(strongNameSignature.toDataType(), "StrongNameSignature", null);
		struct.add(codeManagerTable.toDataType(), "CodeManagerTable", "Should be 0");
		struct.add(vTableFixups.toDataType(), "VTableFixups", null);
		struct.add(exportAddressTableJumps.toDataType(), "ExportAddressTableJumps", "Should be 0");
		struct.add(managedNativeHeader.toDataType(), "ManagedNativeHeader",
			"0 unless this is a native image");
		struct.setCategoryPath(new CategoryPath("/PE"));
		return struct;
	}

	/**
	 * Gets the size of this structure in bytes.
	 *
	 * @return The size of this structure in bytes.
	 */
	public int getCb() {
		return cb;
	}

	/**
	 * Gets the major runtime version.
	 *
	 * @return The major runtime version.
	 */
	public short getMajorRuntimeVersion() {
		return majorRuntimeVersion;
	}

	/**
	 * Gets the major runtime version.
	 *
	 * @return The major runtime version.
	 */
	public short getMinorRuntimeVersion() {
		return minorRuntimeVersion;
	}

	/**
	 * Gets the MetaData directory.
	 *
	 * @return The MetaData directory.
	 */
	public CliMetadataDirectory getMetadata() {
		return metadata;
	}

	/**
	 * Gets the flags.
	 *
	 * @return The flags.
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * Gets the entry point token.
	 *
	 * @return The entry point token.
	 */
	public int getEntryPointToken() {
		return entryPointToken;
	}

	/**
	 * Gets the entry point virtual address.
	 *
	 * @return The entry point address.
	 */
	public Address getEntryPointVA() {
		return entryPointVA;
	}

	/**
	 * Gets the Resources directory.
	 *
	 * @return The Resources directory.
	 */
	public DefaultDataDirectory getResources() {
		return resources;
	}

	/**
	 * Gets the StrongNameSignature directory.
	 * @return The StrongNameSignature directory.
	 */
	public DefaultDataDirectory getStrongNameSignature() {
		return strongNameSignature;
	}

	/**
	 * Gets the CodeManagerTable directory.
	 * @return The CodeManagerTable directory.
	 */
	public DefaultDataDirectory getCodeManagerTable() {
		return codeManagerTable;
	}

	/**
	 * Gets the VTableFixups directory.
	 * @return The VTableFixups directory.
	 */
	public DefaultDataDirectory getVTableFixups() {
		return vTableFixups;
	}

	/**
	 * Gets the ExportAddressTableJumps directory.
	 * @return The ExportAddressTableJumps directory.
	 */
	public DefaultDataDirectory getExportAddressTableJumps() {
		return exportAddressTableJumps;
	}

	/**
	 * Gets the ManagedNativeHeader directory.
	 * @return The ManagedNativeHeader directory.
	 */
	public DefaultDataDirectory getManagedNativeHeader() {
		return managedNativeHeader;
	}

	/**
	 * Data type for {@link ImageCor20Header#flags}.
	 */
	public static class ImageCor20Flags extends EnumDataType {

		public static final String PATH = "/PE/CLI/Flags";

		public static final int COMIMAGE_FLAGS_ILONLY = 0x00000001;
		public static final int COMIMAGE_FLAGS_32BITREQUIRED = 0x00000002;
		public static final int COMIMAGE_FLAGS_IL_LIBRARY = 0x00000004;
		public static final int COMIMAGE_FLAGS_STRONGNAMESIGNED = 0x00000008;
		public static final int COMIMAGE_FLAGS_NATIVE_ENTRYPOINT = 0x00000010;
		public static final int COMIMAGE_FLAGS_TRACKDEBUGDATA = 0x00010000;

		public ImageCor20Flags() {
			super(new CategoryPath(PATH), "COR20_Flags", 4);
			String prefix = "COMIMAGE_FLAGS_";
			add(prefix + "ILONLY", COMIMAGE_FLAGS_ILONLY);
			add(prefix + "32BITREQUIRED", COMIMAGE_FLAGS_32BITREQUIRED);
			add(prefix + "IL_LIBRARY", COMIMAGE_FLAGS_IL_LIBRARY);
			add(prefix + "STRONGNAMESIGNED", COMIMAGE_FLAGS_STRONGNAMESIGNED);
			add(prefix + "NATIVE_ENTRYPOINT", COMIMAGE_FLAGS_NATIVE_ENTRYPOINT);
			add(prefix + "TRACKDEBUGDATA", COMIMAGE_FLAGS_TRACKDEBUGDATA);
		}
	}
}
