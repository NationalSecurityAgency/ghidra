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
package ghidra.file.formats.dump.pagedump;

import java.io.IOException;

import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;

public class TriageDump implements StructConverter {

	public final static String NAME = "PAGEDUMP_TRIAGE";

	private int servicePackBuild;
	private int sizeOfDump;
	private int validOffset;
	private int contextOffset;
	private int exceptionOffset;
	private int mmOffset;
	private int unloadedDriversOffset;
	private int prcbOffset;
	private int processOffset;
	private int threadOffset;
	private int callStackOffset;
	private int callStackSize;
	private int driverListOffset;
	private int driverCount;
	private int stringPoolOffset;
	private int stringPoolSize;
	private int brokenDriverOffset;
	private int triageOptions;
	private long topOfStack;
	private int bStoreOffset;
	private int bStoreSize;
	private long bStoreLimit;

	private long dataPageAddress;
	private int dataPageOffset;
	private int dataPageSize;

	private int debuggerDataOffset;
	private int debuggerDataSize;
	private int dataBlocksOffset;
	private int dataBlocksCount;

	private DumpFileReader reader;
	private long index;
	private int psz;
	private boolean is32Bit;

	TriageDump(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();
		this.is32Bit = psz == 4;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setServicePackBuild(reader.readNextInt());
		setSizeOfDump(reader.readNextInt());
		setValidOffset(reader.readNextInt());
		setContextOffset(reader.readNextInt());
		setExceptionOffset(reader.readNextInt());
		setMmOffset(reader.readNextInt());
		setUnloadedDriversOffset(reader.readNextInt());
		setPrcbOffset(reader.readNextInt());
		setProcessOffset(reader.readNextInt());
		setThreadOffset(reader.readNextInt());
		setCallStackOffset(reader.readNextInt());
		setCallStackSize(reader.readNextInt());
		setDriverListOffset(reader.readNextInt());
		setDriverCount(reader.readNextInt());
		setStringPoolOffset(reader.readNextInt());
		setStringPoolSize(reader.readNextInt());
		setBrokenDriverOffset(reader.readNextInt());
		setTriageOptions(reader.readNextInt());
		setTopOfStack(reader.readNextPointer());
		setBStoreOffset(reader.readNextInt());
		setBStoreSize(reader.readNextInt());
		setBStoreLimit(reader.readNextPointer());
		if (!is32Bit) {
			setDataPageAddress(reader.readNextLong());
			setDataPageOffset(reader.readNextInt());
			setDataPageSize(reader.readNextInt());
		}
		setDebuggerDataOffset(reader.readNextInt());
		setDebuggerDataSize(reader.readNextInt());
		setDataBlocksOffset(reader.readNextInt());
		setDataBlocksCount(reader.readNextInt());
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "ServicePackBuild", null);
		struct.add(DWORD, 4, "SizeOfDump", null);
		struct.add(DWORD, 4, "ValidOffset", null);
		struct.add(Pointer32DataType.dataType, 4, "ContextOffset", null);
		struct.add(Pointer32DataType.dataType, 4, "ExceptionOffset", null);
		struct.add(Pointer32DataType.dataType, 4, "MmOffset", null);
		struct.add(Pointer32DataType.dataType, 4, "UnloadedDriversOffset", null);
		struct.add(Pointer32DataType.dataType, 4, "PrcbOffset", null);
		struct.add(Pointer32DataType.dataType, 4, "ProcessOffset", null);
		struct.add(Pointer32DataType.dataType, 4, "ThreadOffset", null);
		struct.add(Pointer32DataType.dataType, 4, "CallStackOffset", null);
		struct.add(DWORD, 4, "CallStackSize", null);
		struct.add(Pointer32DataType.dataType, 4, "DriverListOffset", null);
		struct.add(DWORD, 4, "DriverCount", null);
		struct.add(Pointer32DataType.dataType, 4, "StringPoolOffset", null);
		struct.add(DWORD, 4, "StringPoolSize", null);
		struct.add(Pointer32DataType.dataType, 4, "BrokenDriverOffset", null);
		struct.add(DWORD, 4, "TriageOptions", null);
		struct.add(POINTER, psz, "TopOfStack", null);
		struct.add(Pointer32DataType.dataType, 4, "BStoreOffset", null);
		struct.add(DWORD, 4, "BStoreSize", null);
		struct.add(POINTER, psz, "BStoreLimit", null);
		if (!is32Bit) {
			struct.add(POINTER, psz, "DataPageAddress", null);
			struct.add(Pointer32DataType.dataType, 4, "DataPageOffset", null);
			struct.add(DWORD, 4, "DataPageSize", null);
		}
		struct.add(Pointer32DataType.dataType, 4, "DebuggerDataOffset", null);
		struct.add(DWORD, 4, "DebuggerDataSize", null);
		struct.add(Pointer32DataType.dataType, 4, "DataBlocksOffset", null);
		struct.add(DWORD, 4, "DataBlocksCount", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public int getServicePackBuild() {
		return servicePackBuild;
	}

	public void setServicePackBuild(int servicePackBuild) {
		this.servicePackBuild = servicePackBuild;
	}

	public int getSizeOfDump() {
		return sizeOfDump;
	}

	public void setSizeOfDump(int sizeOfDump) {
		this.sizeOfDump = sizeOfDump;
	}

	public int getValidOffset() {
		return validOffset;
	}

	public void setValidOffset(int validOffset) {
		this.validOffset = validOffset;
	}

	public int getContextOffset() {
		return contextOffset;
	}

	public void setContextOffset(int contextOffset) {
		this.contextOffset = contextOffset;
	}

	public int getExceptionOffset() {
		return exceptionOffset;
	}

	public void setExceptionOffset(int exceptionOffset) {
		this.exceptionOffset = exceptionOffset;
	}

	public int getMmOffset() {
		return mmOffset;
	}

	public void setMmOffset(int mmOffset) {
		this.mmOffset = mmOffset;
	}

	public int getUnloadedDriversOffset() {
		return unloadedDriversOffset;
	}

	public void setUnloadedDriversOffset(int unloadedDriversOffset) {
		this.unloadedDriversOffset = unloadedDriversOffset;
	}

	public int getPrcbOffset() {
		return prcbOffset;
	}

	public void setPrcbOffset(int prcbOffset) {
		this.prcbOffset = prcbOffset;
	}

	public int getProcessOffset() {
		return processOffset;
	}

	public void setProcessOffset(int processOffset) {
		this.processOffset = processOffset;
	}

	public int getThreadOffset() {
		return threadOffset;
	}

	public void setThreadOffset(int threadOffset) {
		this.threadOffset = threadOffset;
	}

	public int getCallStackOffset() {
		return callStackOffset;
	}

	public void setCallStackOffset(int callStackOffset) {
		this.callStackOffset = callStackOffset;
	}

	public int getCallStackSize() {
		return callStackSize;
	}

	public void setCallStackSize(int callStackSize) {
		this.callStackSize = callStackSize;
	}

	public int getDriverListOffset() {
		return driverListOffset;
	}

	public void setDriverListOffset(int driverListOffset) {
		this.driverListOffset = driverListOffset;
	}

	public int getDriverCount() {
		return driverCount;
	}

	public void setDriverCount(int driverCount) {
		this.driverCount = driverCount;
	}

	public int getStringPoolOffset() {
		return stringPoolOffset;
	}

	public void setStringPoolOffset(int stringPoolOffset) {
		this.stringPoolOffset = stringPoolOffset;
	}

	public int getStringPoolSize() {
		return stringPoolSize;
	}

	public void setStringPoolSize(int stringPoolSize) {
		this.stringPoolSize = stringPoolSize;
	}

	public int getBrokenDriverOffset() {
		return brokenDriverOffset;
	}

	public void setBrokenDriverOffset(int brokenDriverOffset) {
		this.brokenDriverOffset = brokenDriverOffset;
	}

	public int getTriageOptions() {
		return triageOptions;
	}

	public void setTriageOptions(int triageOptions) {
		this.triageOptions = triageOptions;
	}

	public long getTopOfStack() {
		return topOfStack;
	}

	public void setTopOfStack(long topOfStack) {
		this.topOfStack = topOfStack;
	}

	public int getDebuggerDataOffset() {
		return debuggerDataOffset;
	}

	public void setDebuggerDataOffset(int debuggerDataOffset) {
		this.debuggerDataOffset = debuggerDataOffset;
	}

	public int getDebuggerDataSize() {
		return debuggerDataSize;
	}

	public void setDebuggerDataSize(int debuggerDataSize) {
		this.debuggerDataSize = debuggerDataSize;
	}

	public int getDataBlocksOffset() {
		return dataBlocksOffset;
	}

	public void setDataBlocksOffset(int dataBlocksOffset) {
		this.dataBlocksOffset = dataBlocksOffset;
	}

	public int getDataBlocksCount() {
		return dataBlocksCount;
	}

	public void setDataBlocksCount(int dataBlocksCount) {
		this.dataBlocksCount = dataBlocksCount;
	}

	public int getBStoreOffset() {
		return bStoreOffset;
	}

	public void setBStoreOffset(int bStoreOffset) {
		this.bStoreOffset = bStoreOffset;
	}

	public int getBStoreSize() {
		return bStoreSize;
	}

	public void setBStoreSize(int bStoreSize) {
		this.bStoreSize = bStoreSize;
	}

	public long getBStoreLimit() {
		return bStoreLimit;
	}

	public void setBStoreLimit(long bStoreLimit) {
		this.bStoreLimit = bStoreLimit;
	}

	public long getDataPageAddress() {
		return dataPageAddress;
	}

	public void setDataPageAddress(long dataPageAddress) {
		this.dataPageAddress = dataPageAddress;
	}

	public int getDataPageOffset() {
		return dataPageOffset;
	}

	public void setDataPageOffset(int dataPageOffset) {
		this.dataPageOffset = dataPageOffset;
	}

	public int getDataPageSize() {
		return dataPageSize;
	}

	public void setDataPageSize(int dataPageSize) {
		this.dataPageSize = dataPageSize;
	}
}
