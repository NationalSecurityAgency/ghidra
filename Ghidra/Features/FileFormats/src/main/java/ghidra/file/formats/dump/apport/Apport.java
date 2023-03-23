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
package ghidra.file.formats.dump.apport;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.file.formats.dump.DumpFile;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class Apport extends DumpFile {

	public static final int SIGNATURE = 0x626F7250;  // "ProblemType"

	ApportHeader header;

	private MessageLog log;

	public Apport(DumpFileReader reader, ProgramBasedDataTypeManager dtm, List<Option> options,
			TaskMonitor monitor, LoadSpec loadSpec, MessageLog log)
			throws CancelledException, IOException {

		super(reader, dtm, options, monitor);
		this.log = log;

		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString("Executable Format", PeLoader.PE_NAME);
		initManagerList(null);

		header = new ApportHeader(reader, 0L, monitor);
		
		boolean createBlocks =
			OptionUtils.getBooleanOptionValue(CREATE_MEMORY_BLOCKS_OPTION_NAME,
				options, CREATE_MEMORY_BLOCKS_OPTION_DEFAULT);
		if (createBlocks) {
			createBlocksFromElf(loadSpec, monitor);
		}

		buildStructures(loadSpec, monitor);
	}

	@Override
	public boolean joinBlocksEnabled() {
		return false;
	}

	public ApportHeader getFileHeader() {
		return header;
	}

	private void createBlocksFromElf(LoadSpec loadSpec, TaskMonitor monitor)
			throws IOException, CancelledException {

		try (
			DecodedProvider provider =
				new DecodedProvider(this, reader.getByteProvider(), monitor)) {
			ElfLoader elfLoader = new ElfLoader();
			Option base = new Option(ElfLoaderOptionsFactory.IMAGE_BASE_OPTION_NAME,
				Long.toHexString(header.getMemoryInfo(0).getBaseAddress()));
			options.add(base);
			elfLoader.load(provider, loadSpec, options, program, monitor, log);
		}

		Memory memory = program.getMemory();
		Address minAddress = memory.getMinAddress();
		Listing listing = program.getListing();
		ProgramModule root = listing.getDefaultRootModule();
		Group[] children = root.getChildren();

		try {
			for (int i = 0; i < header.getMemoryRegionCount(); i++) {
				MemoryInfo minfo = header.getMemoryInfo(i);
				String id = minfo.getDescription();
				if (id == null) {
					id = "Memory";
				}
				Address addr = minAddress.getNewAddress(minfo.getBaseAddress());
				MemoryBlock block = memory.getBlock(addr);
				if (block != null) {
					String name = block.getName();
					block.setName(id);

					boolean renamed = false;
					try {
						Group fragment = children[root.getIndex(name)];
						if (fragment != null) {
							fragment.setName(i + ":" + id);
							renamed = true;
						}
					}
					catch (DuplicateNameException e) {
						// ignore
					}
					if (!renamed) {
						Msg.error(this, "Failed to rename module: " + name);
					}

				}
			}
		}
		catch (LockException e) {
			throw new IOException(e); // unexpected during import
		}
	}

	private void buildStructures(LoadSpec loadSpec, TaskMonitor monitor)
			throws IOException {

		DataType dt = header.toDataType();

		try {
			ByteProvider byteProvider = reader.getByteProvider();
			MemoryBlock headerBlock = MemoryBlockUtils.createInitializedBlock(program, true,
				"DumpHeader",
				AddressSpace.OTHER_SPACE.getMinAddress(),
				//fileBytes,
				//d.getRVA(), // offset into filebytes
				byteProvider.getInputStream(0),
				dt.getLength(), // size
				byteProvider.getName(), // comment
				"Apport", // source
				true, // section.isReadonly(),
				true, // section.isWriteable(),
				false, //section.isExecutable());
				log,
				monitor);

			program.getListing().createData(headerBlock.getStart(), dt, dt.getLength());
		}
		catch (AddressOverflowException e) {
			throw new AssertException(e);
		}
		catch (CodeUnitInsertionException e) {
			Msg.warn(this, e.getMessage());
		}

	}

	public static String getMachineType(DumpFileReader reader) throws IOException {
		ApportHeader header = new ApportHeader(reader, 0L, TaskMonitor.DUMMY);
		return header.getMachineImageType();
	}

	@Override
	public FileBytes getFileBytes(TaskMonitor monitor) throws IOException, CancelledException {
		// FileBytes not used for original file content
		return null;
	}

	/**
	 * Get default <code>Apport</code> dump loader options.
	 * Limited to {@link DumpFile#CREATE_MEMORY_BLOCKS_OPTION_NAME}.
	 * @param reader dump file reader
	 * @return default collection of Userdump loader options
	 */
	public static Collection<? extends Option> getDefaultOptions(DumpFileReader reader) {
		List<Option> list = new ArrayList<>();

		list.add(new Option(CREATE_MEMORY_BLOCKS_OPTION_NAME, CREATE_MEMORY_BLOCKS_OPTION_DEFAULT,
			Boolean.class, Loader.COMMAND_LINE_ARG_PREFIX + "-createMemoryBlocks"));

		return list;
	}

}
