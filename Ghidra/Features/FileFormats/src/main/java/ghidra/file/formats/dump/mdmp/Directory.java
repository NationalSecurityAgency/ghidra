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

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class Directory implements StructConverter {

	public final static String NAME = "MINIDUMP_DIRECTORY";

	public final static int THREAD_LIST_STREAM = 3;
	public final static int MODULE_LIST_STREAM = 4;
	public final static int MEMORY_LIST_STREAM = 5;
	public final static int EXCEPTION_STREAM = 6;
	public final static int SYSTEM_INFO_STREAM = 7;
	public final static int THREAD_EX_LIST_STREAM = 8;
	public final static int MEMORY64_LIST_STREAM = 9;
	public final static int HANDLE_LIST_STREAM = 0xC;
	public final static int UNLOADED_MODULE_LIST_STREAM = 0xE;
	public final static int MISC_INFO_STREAM = 0xF;
	public final static int MEMORY_INFO_LIST_STREAM = 0x10;
	public final static int TOKEN_LIST_STREAM = 0x13;

	private final static String[] names = {
		"UnusedStream", "ReservedStream0", "ReservedStream1", "ThreadListStream",
		"ModuleListStream", "MemoryListStream", "ExceptionStream", "SystemInfoStream ",
		"ThreadExListStream", "Memory64ListStream", "CommentStreamA", "CommentStreamW",
		"HandleDataStream", "FunctionTableStream", "UnloadedModuleListStream", "MiscInfoStream",
		"MemoryInfoListStream", "ThreadInfoListStream", "HandleOperationListStream",
		"TokenStream", "JavaScriptDataStream", "SystemMemoryInfoStream", "ProcessVmCountersStream",
		"IptTraceStream", "ThreadNamesStream"
	};

	private int streamType;
	private int dataSize;
	private long rva;

	private DumpFileReader reader;
	private long index;

	Directory(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setStreamType(reader.readNextInt());
		setDataSize(reader.readNextInt());
		setRVA(reader.readNextInt());
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "StreamType", null);
		struct.add(DWORD, 4, "DataSize", null);
		struct.add(Pointer32DataType.dataType, 4, "RVA", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public void setStreamType(int streamType) {
		this.streamType = streamType;
	}

	public int getStreamType() {
		return streamType;
	}

	public void setDataSize(int dataSize) {
		this.dataSize = dataSize;
	}

	public int getDataSize() {
		return dataSize;
	}

	public void setRVA(long rva) {
		this.rva = rva;
	}

	public long getRVA() {
		return rva;
	}

	public String getReadableName() {
		return names[streamType];
	}

}
