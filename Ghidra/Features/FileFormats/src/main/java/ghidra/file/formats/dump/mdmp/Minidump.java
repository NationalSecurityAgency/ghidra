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
package ghidra.file.formats.dump.mdmp;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.opinion.PeLoader;
import ghidra.file.formats.dump.*;
import ghidra.file.formats.dump.cmd.ModuleToPeHelper;
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class Minidump extends DumpFile {

	public static final int SIGNATURE = 0x504D444D;  // "PAGE"

	MdmpFileHeader header;
	Directory[] dirs;
	HashMap<Integer, StructConverter> streams = new HashMap<Integer, StructConverter>();
	private boolean createBlocks;

	public Minidump(DumpFileReader reader, ProgramBasedDataTypeManager dtm, List<Option> options,
			TaskMonitor monitor) {

		super(reader, dtm, options, monitor);

		Options props = program.getOptions(Program.PROGRAM_INFO);
		props.setString("Executable Format", PeLoader.PE_NAME);
		initManagerList(null);

		createBlocks =
			OptionUtils.getBooleanOptionValue(CREATE_MEMORY_BLOCKS_OPTION_NAME,
				options, CREATE_MEMORY_BLOCKS_OPTION_DEFAULT);

		try {
			header = new MdmpFileHeader(reader, 0L);
			data.add(new DumpData(0, header.toDataType()));

			dirs = new Directory[header.getNumberOfStreams()];
			for (int i = 0; i < dirs.length; i++) {
				dirs[i] = new Directory(reader, reader.getPointerIndex());
			}
			for (Directory dir : dirs) {
				long rva = dir.getRVA();
				StructConverter sv = null;
				switch (dir.getStreamType()) {
					case 3:
						sv = new ThreadListStream(reader, rva);
						break;
					case 4:
						sv = new ModuleListStream(reader, rva);
						break;
					case 5:
						sv = new MemoryListStream(reader, rva);
						break;
					case 6:
						sv = new ExceptionStream(reader, rva);
						break;
					case 7:
						sv = new SystemInfoStream(reader, rva);
						break;
					case 8:
						sv = new ThreadExListStream(reader, rva);
						break;
					case 9:
						sv = new Memory64ListStream(reader, rva);
						break;
					case 10:
						sv = new CommentStreamA(reader, rva);
						break;
					case 11:
						sv = new CommentStreamW(reader, rva);
						break;
					case 12:
						sv = new HandleDataStream(reader, rva);
						break;
					case 13:
						sv = new FunctionTableStream(reader, rva);
						break;
					case 14:
						sv = new UnloadedModuleListStream(reader, rva);
						break;
					case 15:
						sv = new MiscInfoStream(reader, rva);
						break;
					case 16:
						sv = new MemoryInfoListStream(reader, rva);
						break;
					case 17:
						sv = new ThreadInfoListStream(reader, rva);
						break;
					case 18:
						sv = new HandleOperationListStream(reader, rva);
						break;
					case 19:
						sv = new TokenListStream(reader, rva);
						break;
					case 20:
						//sv = new JavaScriptDataStream(reader, rva);
						break;
					case 21:
						sv = new SystemMemoryInfoStream(reader, rva);
						break;
					case 22:
						sv = new ProcessVmCountersStream(reader, rva);
						break;
					case 23:
						//sv = new IptTraceStream(reader, rva);
						break;
					case 24:
						//sv = new ThreadNamesStream(reader, rva);
						break;
				}
				if (sv != null) {
					streams.put(dir.getStreamType(), sv);
				}

			}

			buildStructures();

		}
		catch (Exception e) {
			Msg.error(this, e.getMessage());
		}
	}

	private void buildStructures() throws Exception {
		long offset = header.toDataType().getLength();

		long headerMax = offset;
		DataType dt = dirs[0].toDataType();
		data.add(new DumpData(offset, "DIRECTORIES", dt.getLength() * dirs.length));
		for (int i = 0; i < dirs.length; ++i) {
			offset = header.getStreamDirectoryRVA() + i * dt.getLength();
			data.add(new DumpData(offset, dirs[i].toDataType(), "", false, false));
			if (offset + i * dt.getLength() > headerMax) {
				headerMax = offset + i * dt.getLength();
			}
		}
		for (int i = 0; i < dirs.length; ++i) {
			offset = dirs[i].getRVA();
			if (offset > 0) {
				StructConverter stream = getStreamByDir(i);
				if (stream != null) {
					dt = stream.toDataType();
					data.add(new DumpData(offset, dt, dirs[i].getReadableName(), false, true));
					if (offset + dt.getLength() > headerMax) {
						headerMax = offset + dt.getLength();
					}
				}
			}
		}

		// Compute upper bound for header block
		StructConverter sv = getStreamByType(Directory.MEMORY_LIST_STREAM);
		if (sv != null) {
			MemoryListStream memstr = (MemoryListStream) sv;
			for (int i = 0; i < memstr.getNumberOfMemoryRanges(); i++) {
				MemoryRange memoryRange = memstr.getMemoryRange(i);
				if (memoryRange.getStartOfMemoryRange() < headerMax) {
					headerMax = memoryRange.getStartOfMemoryRange();
				}
			}
		}
		sv = getStreamByType(Directory.MEMORY64_LIST_STREAM);
		if (sv != null) {
			Memory64ListStream memstr = (Memory64ListStream) sv;
			for (int i = 0; i < memstr.getNumberOfMemoryRanges(); i++) {
				MemoryRange64 memoryRange = memstr.getMemoryRange(i);
				if (memoryRange.getStartOfMemoryRange() < headerMax) {
					headerMax = memoryRange.getStartOfMemoryRange();
				}
			}
		}
		addInteriorAddressObject("DumpHeader", 0, 0L, headerMax);

		sv = getStreamByType(Directory.MODULE_LIST_STREAM);
		if (sv != null) {
			ModuleListStream modstr = (ModuleListStream) sv;
			for (int i = 0; i < modstr.getNumberOfModules(); i++) {
				Module mod = modstr.getModule(i);
				offset = mod.getModuleNameRVA();

				data.add(new DumpData(offset, StructConverter.DWORD, "", false, false));
				int len = reader.readInt(offset);

				offset += 4;
				DumpData dd =
					new DumpData(offset, new TerminatedUnicodeDataType(), "", false, false);
				dd.setSize(len + 2);
				data.add(dd);

				String moduleName = reader.readUnicodeString(offset, len / 2);
				addModule(moduleName, mod.getBaseOfImage(), i, mod.getSizeOfImage());
				addExteriorAddressObject(moduleName, 0, mod.getBaseOfImage(), mod.getSizeOfImage());

				CvRecord cvRecord = mod.getCvRecord();
				offset = mod.getCvRecordRVA();
				dt = cvRecord.toDataType();
				data.add(new DumpData(offset, dt, "", false, false));
				offset += dt.getLength();
				data.add(new DumpData(offset, new StringDataType(), "", false, false));
			}
		}
		sv = getStreamByType(Directory.UNLOADED_MODULE_LIST_STREAM);
		if (sv != null) {
			UnloadedModuleListStream modstr = (UnloadedModuleListStream) sv;
			for (int i = 0; i < modstr.getNumberOfEntries(); i++) {
				UnloadedModule mod = modstr.getEntry(i);
				offset = mod.getModuleNameRVA();

				data.add(new DumpData(offset, StructConverter.DWORD, "", false, false));
				int len = reader.readInt(offset);

				offset += 4;
				DumpData dd =
					new DumpData(offset, new TerminatedUnicodeDataType(), "", false, false);
				dd.setSize(len + 2);
				data.add(dd);

				String moduleName = reader.readUnicodeString(offset, len / 2);
				addModule(moduleName, mod.getBaseOfImage(), i, mod.getSizeOfImage());
				addExteriorAddressObject(moduleName, 0, mod.getBaseOfImage(), mod.getSizeOfImage());
			}
		}

		if (createBlocks) {
			sv = getStreamByType(Directory.MEMORY_LIST_STREAM);
			if (sv != null) {
				MemoryListStream memstr = (MemoryListStream) sv;
				for (int i = 0; i < memstr.getNumberOfMemoryRanges(); i++) {
					MemoryRange memoryRange = memstr.getMemoryRange(i);
					offset = memoryRange.getRVA();

					addInteriorAddressObject(DumpFileLoader.MEMORY, memoryRange.getRVA(),
						memoryRange.getStartOfMemoryRange(), memoryRange.getDataSize());
				}
			}
			sv = getStreamByType(Directory.MEMORY64_LIST_STREAM);
			if (sv != null) {
				Memory64ListStream memstr = (Memory64ListStream) sv;
				offset = (int) memstr.getBaseRVA();

				for (int i = 0; i < memstr.getNumberOfMemoryRanges(); i++) {
					MemoryRange64 memoryRange = memstr.getMemoryRange(i);

					addInteriorAddressObject(DumpFileLoader.MEMORY, (int) offset,
						memoryRange.getStartOfMemoryRange(), memoryRange.getDataSize());
					offset += memoryRange.getDataSize();
				}
			}
		}
		sv = getStreamByType(Directory.MEMORY_INFO_LIST_STREAM);
		if (sv != null) {
			MemoryInfoListStream meminfostr = (MemoryInfoListStream) sv;
			for (int i = 0; i < meminfostr.getNumberOfEntries(); i++) {
				MemoryInfo memoryInfo = meminfostr.getMemoryInfo(i);
				DumpAddressObject dao = getInteriorAddressObject(memoryInfo.getBaseAddress());
				if (dao != null) {
					dao.setRead((memoryInfo.getProtect() & 0x66) > 0);
					dao.setWrite((memoryInfo.getProtect() & 0xCC) > 0);
					dao.setExec((memoryInfo.getProtect() & 0xF0) > 0);
					dao.setComment(memoryInfo.getComment());
				}
			}
		}

		sv = getStreamByType(Directory.THREAD_LIST_STREAM);
		if (sv != null) {
			ThreadListStream tstr = (ThreadListStream) sv;
			for (int i = 0; i < tstr.getNumberOfThreads(); i++) {
				Thread t = tstr.getThread(i);
				String tid = Integer.toHexString(t.getThreadId());

				offset = t.getContextRVA();
				if (offset != 0) {
					if (contextOffset == 0) {
						contextOffset = offset;
					}
					CategoryPath path = new CategoryPath("/winnt.h");
					dt = getTypeFromArchive(path, "CONTEXT");
					if (dt != null) {
						data.add(new DumpData(offset, dt, "ThreadContext_" + tid, false, true));
						setProgramContext(offset, dt, tid);
					}
				}

				offset = t.getStackRVA();
				if (createBlocks && offset != 0) {
					addInteriorAddressObject("ThreadStack_" + tid, (int) offset,
						t.getStackStartOfMemoryRange(), t.getStackDataSize());
				}
			}
		}
		sv = getStreamByType(Directory.THREAD_EX_LIST_STREAM);
		if (sv != null) {
			ThreadExListStream tstr = (ThreadExListStream) sv;
			for (int i = 0; i < tstr.getNumberOfThreads(); i++) {
				ThreadEx t = tstr.getThread(i);
				String tid = Integer.toHexString(t.getThreadId());

				offset = t.getContextRVA();
				if (offset != 0) {
					CategoryPath path = new CategoryPath("/winnt.h");
					dt = getTypeFromArchive(path, "CONTEXT");
					if (dt != null) {
						data.add(new DumpData(offset, dt, "ThreadContext_" + tid, false, true));
						setProgramContext(offset, dt, tid);
					}
				}

				offset = t.getStackRVA();
				if (createBlocks && offset != 0) {
					addInteriorAddressObject("ThreadStack_" + tid, (int) offset,
						t.getStackStartOfMemoryRange(), t.getStackDataSize());
				}
			}
		}

		sv = getStreamByType(Directory.HANDLE_LIST_STREAM);
		if (sv != null) {
			HandleDataStream handles = (HandleDataStream) sv;
			for (int i = 0; i < handles.getNumberOfHandles(); i++) {
				Handle handle = handles.getHandle(i);

				offset = handle.getTypeNameRVA();
				if (offset > 0) {
					data.add(new DumpData(offset, StructConverter.DWORD, "", false, false));
					int len = reader.readInt(offset);
					offset += 4;
					DumpData ddType =
						new DumpData(offset, new TerminatedUnicodeDataType(), "", false, false);
					ddType.setSize(len + 2);
					data.add(ddType);
				}

				offset = handle.getObjectNameRVA();
				if (offset > 0) {
					data.add(new DumpData(offset, StructConverter.DWORD, "", false, false));
					int len = reader.readInt(offset);
					offset += 4;
					DumpData ddObj =
						new DumpData(offset, new TerminatedUnicodeDataType(), "", false, false);
					ddObj.setSize(len + 2);
					data.add(ddObj);
				}

			}
		}

		sv = getStreamByType(Directory.SYSTEM_INFO_STREAM);
		if (sv != null) {
			SystemInfoStream sistr = (SystemInfoStream) sv;
			offset = sistr.getCSDVersionRVA();
			data.add(new DumpData(offset, StructConverter.DWORD, "", false, false));
			int len = reader.readInt(offset);

			offset += 4;
			DumpData dd =
				new DumpData(offset, new TerminatedUnicodeDataType(), "", false, false);
			dd.setSize(len + 2);
			data.add(dd);
		}
		sv = getStreamByType(Directory.MISC_INFO_STREAM);
		if (sv != null) {
			MiscInfoStream mistr = (MiscInfoStream) sv;
			processId = mistr.getProcessId();
			addProcess(processId, "TARGET", 0);
		}
		sv = getStreamByType(Directory.EXCEPTION_STREAM);
		if (sv != null) {
			ExceptionStream xstr = (ExceptionStream) sv;
			offset = xstr.getContextRVA();
			contextOffset = offset;
			dt = xstr.getDefaultContext();
			data.add(new DumpData(offset, dt));

			threadId = xstr.getThreadId();
			addThread(processId, threadId, 0);
		}
	}

	public MdmpFileHeader getFileHeader() {
		return header;
	}

	public Directory[] getDirectories() {
		return dirs;
	}

	public StructConverter getStreamByType(int type) {
		return streams.get(type);
	}

	public StructConverter getStreamByDir(int dirIndex) {
		return streams.get(dirs[dirIndex].getStreamType());
	}

	public static String getMachineType(DumpFileReader reader) throws IOException {
		MdmpFileHeader header = new MdmpFileHeader(reader, 0L);
		Directory[] dirs = new Directory[header.getNumberOfStreams()];
		for (int i = 0; i < dirs.length; i++) {
			dirs[i] = new Directory(reader, reader.getPointerIndex());
		}
		for (Directory dir : dirs) {
			long rva = dir.getRVA();
			switch (dir.getStreamType()) {
				case 7:
					SystemInfoStream sv = new SystemInfoStream(reader, rva);
					return Integer.toString(sv.getProcessorArchitecture());
			}
		}
		return "0";
	}

	@Override
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
	 * Get default <code>Minidump</code> loader options.
	 * See {@link DumpFile#getDefaultOptions(DumpFileReader)}.
	 * @param reader dump file reader
	 * @return default collection of Minidump loader options
	 */
	public static Collection<? extends Option> getDefaultOptions(DumpFileReader reader) {
		// Use DumpFile default options
		return DumpFile.getDefaultOptions(reader);
	}
}
