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

public class ThreadEx implements StructConverter {

	public final static String NAME = "MINIDUMP_THREAD_EX";

	private int threadId;
	private int suspendCount;
	private int priorityClass;
	private int platformId;
	private int priority;
	private long teb;
	private long stackStartOfMemoryRange;
	private int stackDataSize;
	private int stackRVA;
	private int contextDataSize;
	private int contextRVA;
	private long backingStoreStartOfMemoryRange;
	private int backingStoreDataSize;
	private int backingStoreRVA;

	private DumpFileReader reader;
	private long index;

	ThreadEx(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setThreadId(reader.readNextInt());
		setSuspendCount(reader.readNextInt());
		setPriorityClass(reader.readNextInt());
		setPriority(reader.readNextInt());
		setTeb(reader.readNextLong());
		setStackStartOfMemoryRange(reader.readNextLong());
		setStackDataSize(reader.readNextInt());
		setStackRVA(reader.readNextInt());
		setContextDataSize(reader.readNextInt());
		setContextRVA(reader.readNextInt());
		setBackingStoreStartOfMemoryRange(reader.readNextLong());
		setBackingStoreDataSize(reader.readNextInt());
		setBackingStoreRVA(reader.readNextInt());

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "ThreadId", null);
		struct.add(DWORD, 4, "SuspendCount", null);
		struct.add(DWORD, 4, "PriorityClass", null);
		struct.add(DWORD, 4, "Priority", null);
		struct.add(QWORD, 8, "Teb", null);

		StructureDataType s0 = new StructureDataType("Stack", 0);
		s0.add(DWORD, 4, "StartOfMemoryRange", null);
		s0.add(DWORD, 4, "DataSize", null);
		s0.add(Pointer32DataType.dataType, 4, "RVA", null);

		StructureDataType s1 = new StructureDataType("Context", 0);
		s1.add(DWORD, 4, "DataSize", null);
		s1.add(Pointer32DataType.dataType, 4, "RVA", null);

		StructureDataType s2 = new StructureDataType("BackingStore", 0);
		s2.add(DWORD, 4, "StartOfMemoryRange", null);
		s2.add(DWORD, 4, "DataSize", null);
		s2.add(Pointer32DataType.dataType, 4, "RVA", null);

		struct.add(s0, s0.getLength(), s0.getDisplayName(), null);
		struct.add(s1, s1.getLength(), s1.getDisplayName(), null);
		struct.add(s2, s2.getLength(), s2.getDisplayName(), null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public int getThreadId() {
		return threadId;
	}

	public void setThreadId(int threadId) {
		this.threadId = threadId;
	}

	public int getSuspendCount() {
		return suspendCount;
	}

	public void setSuspendCount(int suspendCount) {
		this.suspendCount = suspendCount;
	}

	public int getPriorityClass() {
		return priorityClass;
	}

	public void setPriorityClass(int priorityClass) {
		this.priorityClass = priorityClass;
	}

	public int getPlatformId() {
		return platformId;
	}

	public void setPlatformId(int platformId) {
		this.platformId = platformId;
	}

	public int getPriority() {
		return priority;
	}

	public void setPriority(int priority) {
		this.priority = priority;
	}

	public long getTeb() {
		return teb;
	}

	public void setTeb(long teb) {
		this.teb = teb;
	}

	public long getStackStartOfMemoryRange() {
		return stackStartOfMemoryRange;
	}

	public void setStackStartOfMemoryRange(long stackStartOfMemoryRange) {
		this.stackStartOfMemoryRange = stackStartOfMemoryRange;
	}

	public int getStackDataSize() {
		return stackDataSize;
	}

	public void setStackDataSize(int stackDataSize) {
		this.stackDataSize = stackDataSize;
	}

	public int getStackRVA() {
		return stackRVA;
	}

	public void setStackRVA(int stackRVA) {
		this.stackRVA = stackRVA;
	}

	public int getContextDataSize() {
		return contextDataSize;
	}

	public void setContextDataSize(int contextDataSize) {
		this.contextDataSize = contextDataSize;
	}

	public int getContextRVA() {
		return contextRVA;
	}

	public void setContextRVA(int contextRVA) {
		this.contextRVA = contextRVA;
	}

	public void setBackingStoreStartOfMemoryRange(
			long backingStoreStartOfMemoryRange) {
		this.backingStoreStartOfMemoryRange = backingStoreStartOfMemoryRange;
	}

	public long getBackingStoreStartOfMemoryRange() {
		return backingStoreStartOfMemoryRange;
	}

	public void setBackingStoreDataSize(int backingStoreDataSize) {
		this.backingStoreDataSize = backingStoreDataSize;
	}

	public int getBackingStoreDataSize() {
		return backingStoreDataSize;
	}

	public void setBackingStoreRVA(int backingStoreRVA) {
		this.backingStoreRVA = backingStoreRVA;
	}

	public int getBackingStoreRVA() {
		return backingStoreRVA;
	}

}
