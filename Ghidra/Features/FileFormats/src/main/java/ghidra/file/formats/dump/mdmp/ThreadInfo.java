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

public class ThreadInfo implements StructConverter {

	public final static String NAME = "MINIDUMP_THREAD_INFO";

	private int threadId;
	private int dumpFlags;
	private int dumpError;
	private int exitStatus;
	private long createTime;
	private long exitTime;
	private long kernelTime;
	private long userTime;
	private long startAddress;
	private long affinity;

	private DumpFileReader reader;
	private long index;

	ThreadInfo(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setThreadId(reader.readNextInt());
		setDumpFlags(reader.readNextInt());
		setDumpError(reader.readNextInt());
		setExitStatus(reader.readNextInt());
		setCreateTime(reader.readNextLong());
		setExitTime(reader.readNextLong());
		setKernelTime(reader.readNextLong());
		setUserTime(reader.readNextLong());
		setStartAddress(reader.readNextLong());
		setAffinity(reader.readNextLong());

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "ThreadId", null);
		struct.add(DWORD, 4, "DumpFlags", null);
		struct.add(DWORD, 4, "DumpError", null);
		struct.add(DWORD, 4, "ExitStatus", null);
		struct.add(QWORD, 8, "CreateTime", null);
		struct.add(QWORD, 8, "ExitTime", null);
		struct.add(QWORD, 8, "KernelTime", null);
		struct.add(QWORD, 8, "UserTime", null);
		struct.add(QWORD, 8, "StartAddress", null);
		struct.add(QWORD, 8, "Affinity", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public int getThreadId() {
		return threadId;
	}

	public void setThreadId(int threadId) {
		this.threadId = threadId;
	}

	public int getDumpFlags() {
		return dumpFlags;
	}

	public void setDumpFlags(int dumpFlags) {
		this.dumpFlags = dumpFlags;
	}

	public int getDumpError() {
		return dumpError;
	}

	public void setDumpError(int dumpError) {
		this.dumpError = dumpError;
	}

	public int getExitStatus() {
		return exitStatus;
	}

	public void setExitStatus(int exitStatus) {
		this.exitStatus = exitStatus;
	}

	public long getCreateTime() {
		return createTime;
	}

	public void setCreateTime(long createTime) {
		this.createTime = createTime;
	}

	public long getExitTime() {
		return exitTime;
	}

	public void setExitTime(long exitTime) {
		this.exitTime = exitTime;
	}

	public long getKernelTime() {
		return kernelTime;
	}

	public void setKernelTime(long kernelTime) {
		this.kernelTime = kernelTime;
	}

	public long getUserTime() {
		return userTime;
	}

	public void setUserTime(long userTime) {
		this.userTime = userTime;
	}

	public long getStartAddress() {
		return startAddress;
	}

	public void setStartAddress(long startAddress) {
		this.startAddress = startAddress;
	}

	public long getAffinity() {
		return affinity;
	}

	public void setAffinity(long affinity) {
		this.affinity = affinity;
	}
}
