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
package ghidra.file.formats.dump.userdump;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.opinion.PeLoader;
import ghidra.file.formats.dump.*;
import ghidra.file.formats.dump.cmd.ModuleToPeHelper;
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class Userdump extends DumpFile {

	public static final int SIGNATURE = 0x52455355;  // "USER"

	UserdumpFileHeader header;
	private boolean createBlocks;

	public Userdump(DumpFileReader reader, ProgramBasedDataTypeManager dtm, List<Option> options,
			TaskMonitor monitor) {

		super(reader, dtm, options, monitor);

		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString("Executable Format", PeLoader.PE_NAME);
		initManagerList(null);

		createBlocks =
			OptionUtils.getBooleanOptionValue(CREATE_MEMORY_BLOCKS_OPTION_NAME,
				options, CREATE_MEMORY_BLOCKS_OPTION_DEFAULT);

		try {

			header = new UserdumpFileHeader(reader, 0L);
			data.add(new DumpData(0, header.toDataType()));

			buildStructures();

		}
		catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	public UserdumpFileHeader getFileHeader() {
		return header;
	}

	private void buildStructures() throws Exception {

		DataType dt = header.toDataType();
		data.add(new DumpData(0, "DumpHeader", dt.getLength()));

		int regionOffset = (int) header.getMemoryRegionOffset();
		addInteriorAddressObject("DumpHeader", 0, 0L, regionOffset);
		int blocksLength = (int) (reader.length() - regionOffset);
		addInteriorAddressObject("RawBlocks", regionOffset,
			header.getMemoryRegionOffset(), blocksLength);

		CategoryPath path = new CategoryPath("/winnt.h");
		long offset = header.getThreadOffset();
		DataType ctxt = getTypeFromArchive(path, "CONTEXT");
		if (ctxt != null) {
			ArrayDataType actxt =
				new ArrayDataType(ctxt, header.getThreadCount(), ctxt.getLength());
			data.add(new DumpData(offset, actxt, "THREAD_CONTEXTS", false, true));
			for (int t = 0; t < header.getThreadCount(); t++) {
				setProgramContext(offset + t * ctxt.getLength(), ctxt, Integer.toHexString(t));
			}
		}

		offset = header.getThreadStateOffset();
		long start = offset;
		reader.setPointerIndex(offset);
		for (int i = 0; i < header.getThreadCount(); i++) {
			Thread t = new Thread(reader, offset);
			String tid = Integer.toHexString(t.getThreadId());
			dt = t.toDataType();

			long stackOffset = t.getStackRVA();
			if (createBlocks && stackOffset != 0) {
				addInteriorAddressObject("ThreadStack_" + tid, (int) stackOffset,
					t.getStackStartOfMemoryRange(), t.getStackDataSize());
			}
			offset += dt.getLength();
		}
		ArrayDataType athreads = new ArrayDataType(dt, header.getThreadCount(), 0x50);
		data.add(new DumpData(start, athreads, "THREAD_INFO", false, true));

		offset = header.getModuleOffset();
		start = offset;
		StructureDataType modulesDT = new StructureDataType("MODULE_INFO", 0);
		for (int i = 0; i < header.getModuleCount(); i++) {
			Module m = new Module(reader, offset);

			dt = m.toDataType();

			modulesDT.add(dt, dt.getLength(), m.getModuleName(), null);
			addModule(m.getModuleName(), m.getModuleBase(), i, m.getModuleSize());
			addExteriorAddressObject(m.getModuleName(), 0, m.getModuleBase(), m.getModuleSize());
			offset += dt.getLength();
		}
		data.add(new DumpData(start, modulesDT, "MODULE_INFO", false, false));

		long rva = header.getMemoryRegionOffset();
		offset = header.getMemoryDescriptorOffset();
		start = offset;
		StructureDataType blocks = new StructureDataType("MEMORY_BLOCKS", 0);
		for (int i = 0; i < header.getMemoryRegionCount(); i++) {
			MemoryInfo minfo = new MemoryInfo(reader, offset);
			dt = minfo.toDataType();

			long regionSize = minfo.getRegionSize();
			if (createBlocks) {
				addInteriorAddressObject("Memory", (int) rva, minfo.getBaseAddress(), regionSize);
			}
			//ArrayDataType block =
			//	new ArrayDataType(ByteDataType.dataType, (int) regionSize, 1);
			//blocks.add(block, (int) regionSize,
			//	"MemoryBlock_" + Long.toHexString(minfo.getBaseAddress()), null);

			rva += regionSize;
			offset += dt.getLength();
		}
		ArrayDataType ainfo = new ArrayDataType(dt, header.getMemoryRegionCount(), dt.getLength());
		data.add(new DumpData(start, ainfo, "MEMORY_INFO", false, true));
		data.add(new DumpData(regionOffset, blocks, "MEMORY_BLOCKS", false, true));

		offset = header.getDebugEventOffset();
		DebugInfo debugInfo = new DebugInfo(reader, offset);
		data.add(new DumpData(offset, debugInfo.toDataType(), "DEBUG_EVENT_INFO", false, true));

		processId = debugInfo.getProcessId();
		threadId = debugInfo.getThreadId();
		addProcess(processId, "TARGET", 0);
		addThread(processId, threadId, 0);

	}

	public static String getMachineType(DumpFileReader reader) throws IOException {
		UserdumpFileHeader header = new UserdumpFileHeader(reader, 0L);
		return Integer.toHexString(header.getMachineImageType());
	}

	public void analyze(TaskMonitor monitor) {
		boolean analyzeEmbeddedObjects =
			OptionUtils.getBooleanOptionValue(ANALYZE_EMBEDDED_OBJECTS_OPTION_NAME,
				options,
				ANALYZE_EMBEDDED_OBJECTS_OPTION_DEFAULT);
		if (analyzeEmbeddedObjects) {
			ModuleToPeHelper.queryModules(program, monitor);
		}
	}

	/**
	 * Get default <code>Userdump</code> loader options.
	 * See {@link DumpFile#getDefaultOptions(DumpFileReader)}.
	 * @param reader dump file reader
	 * @return default collection of Userdump loader options
	 */
	public static Collection<? extends Option> getDefaultOptions(DumpFileReader reader) {
		// Use DumpFile default options
		return DumpFile.getDefaultOptions(reader);
	}
}
