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

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class UserdumpFileHeader implements StructConverter {

	public final static String NAME = "USERDUMP_HEADER";

	private int signature;
	private int validDump;
	private int majorVersion;
	private int minorVersion;
	private int machineImageType;
	private int threadCount;
	private int moduleCount;
	private int memoryRegionCount;
	private long threadOffset;
	private long moduleOffset;
	private long memoryRegionOffset;
	private long memoryDescriptorOffset;
	private long debugEventOffset;
	private long threadStateOffset;

	protected DumpFileReader reader;
	protected long index;
	private int psz;

	UserdumpFileHeader(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();
		parse();
	}

	protected void parse() throws IOException {
		reader.setPointerIndex(index);

		setSignature(reader.readNextInt());
		setValidDump(reader.readNextInt());
		setMajorVersion(reader.readNextInt());
		setMinorVersion(reader.readNextInt());
		setMachineImageType(reader.readNextInt());
		setThreadCount(reader.readNextInt());
		setModuleCount(reader.readNextInt());
		setMemoryRegionCount(reader.readNextInt());
		setThreadOffset(readNextPointer());
		setModuleOffset(readNextPointer());
		setMemoryRegionOffset(readNextPointer());
		setMemoryDescriptorOffset(readNextPointer());
		setDebugEventOffset(readNextPointer());
		setThreadStateOffset(readNextPointer());

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		Structure struct = new StructureDataType(NAME, 0);

		struct.add(STRING, 4, "Signature", null);
		struct.add(STRING, 4, "ValidDump", null);
		struct.add(DWORD, 4, "MajorVersion", null);
		struct.add(DWORD, 4, "MinorVersion", null);
		struct.add(DWORD, 4, "MachineImageType", null);
		struct.add(DWORD, 4, "NumberOfThreads", null);
		struct.add(DWORD, 4, "ModuleCount", null);
		struct.add(DWORD, 4, "MemoryRegionCount", null);
		struct.add(POINTER, psz, "ThreadContextOffset", null);
		struct.add(POINTER, psz, "ModulesOffset", null);
		struct.add(POINTER, psz, "MemoryRegionOffset", null);
		struct.add(POINTER, psz, "MemoryDescriptorOffset", null);
		struct.add(POINTER, psz, "DebugEventOffset", null);
		struct.add(POINTER, psz, "ThreadStateOffset", null);

		struct.setCategoryPath(new CategoryPath("/UDMP"));

		return struct;
	}

	public int getSignature() {
		return signature;
	}

	public void setSignature(int signature) {
		this.signature = signature;
	}

	public int getValidDump() {
		return validDump;
	}

	public void setValidDump(int validDump) {
		this.validDump = validDump;
	}

	public int getMajorVersion() {
		return majorVersion;
	}

	public void setMajorVersion(int majorVersion) {
		this.majorVersion = majorVersion;
	}

	public int getMinorVersion() {
		return minorVersion;
	}

	public void setMinorVersion(int minorVersion) {
		this.minorVersion = minorVersion;
	}

	public int getMachineImageType() {
		return machineImageType;
	}

	public void setMachineImageType(int machineImageType) {
		this.machineImageType = machineImageType;
	}

	public int getThreadCount() {
		return threadCount;
	}

	public void setThreadCount(int threadCount) {
		this.threadCount = threadCount;
	}

	public int getModuleCount() {
		return moduleCount;
	}

	public void setModuleCount(int moduleCount) {
		this.moduleCount = moduleCount;
	}

	public int getMemoryRegionCount() {
		return memoryRegionCount;
	}

	public void setMemoryRegionCount(int memoryRegionCount) {
		this.memoryRegionCount = memoryRegionCount;
	}

	public long getThreadOffset() {
		return threadOffset;
	}

	public void setThreadOffset(long threadOffset) {
		this.threadOffset = threadOffset;
	}

	public long getModuleOffset() {
		return moduleOffset;
	}

	public void setModuleOffset(long moduleOffset) {
		this.moduleOffset = moduleOffset;
	}

	public long getMemoryRegionOffset() {
		return memoryRegionOffset;
	}

	public void setMemoryRegionOffset(long memoryRegionOffset) {
		this.memoryRegionOffset = memoryRegionOffset;
	}

	public long getMemoryDescriptorOffset() {
		return memoryDescriptorOffset;
	}

	public void setMemoryDescriptorOffset(long memoryDescriptorOffset) {
		this.memoryDescriptorOffset = memoryDescriptorOffset;
	}

	public long getDebugEventOffset() {
		return debugEventOffset;
	}

	public void setDebugEventOffset(long debugEventOffset) {
		this.debugEventOffset = debugEventOffset;
	}

	public long getThreadStateOffset() {
		return threadStateOffset;
	}

	public void setThreadStateOffset(long threadStateOffset) {
		this.threadStateOffset = threadStateOffset;
	}

	private long readNextPointer() throws IOException {
		return psz == 4 ? reader.readNextInt() : reader.readNextLong();
	}

}
