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

public class DebugInfo implements StructConverter {

	public final static String NAME = "DEBUG_EVENT";

	private int eventCode;
	private int processId;
	private int threadId;
	private int exceptionCode;
	private int exceptionFlags;
	private long exceptionRecord;
	private long exceptionAddress;
	private int numberOfParameters;
	private long parameters[] = new long[16];

	private long index;
	private int psz;

	DebugInfo(DumpFileReader reader, long index) throws IOException {
		this.index = index;
		this.psz = reader.getPointerSize();

		parse(reader);
	}

	private void parse(DumpFileReader reader) throws IOException {
		reader.setPointerIndex(index);

		setEventCode(reader.readNextInt());
		setProcessId(reader.readNextInt());
		setThreadId(reader.readNextInt());
		reader.readNextInt();
		setExceptionCode(reader.readNextInt());
		setExceptionFlags(reader.readNextInt());
		setExceptionRecord(reader.readNextPointer());
		setExceptionAddress(reader.readNextPointer());
		numberOfParameters = reader.readNextInt();
		for (int i = 0; i < numberOfParameters; i++) {
			parameters[i] = reader.readNextPointer();
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(StructConverter.DWORD, 4, "EventCode", null);
		struct.add(StructConverter.DWORD, 4, "ProcessId", null);
		struct.add(StructConverter.DWORD, 4, "ThreadId", null);
		struct.add(StructConverter.DWORD, 4, "_alignment", null);
		struct.add(StructConverter.DWORD, 4, "ExceptionCode", null);
		struct.add(StructConverter.DWORD, 4, "ExceptionFlags", null);
		struct.add(StructConverter.POINTER, psz, "pExceptionRecord", null);
		struct.add(StructConverter.POINTER, psz, "ExceptionAddress", null);
		struct.add(StructConverter.DWORD, 4, "NumberOfParameters", null);
		for (int i = 0; i < numberOfParameters; i++) {
			struct.add(StructConverter.POINTER, psz, "Param_" + i, null);
		}

		struct.setCategoryPath(new CategoryPath("/UDMP"));

		return struct;
	}

	/**
	 * @return the processId
	 */
	public int getProcessId() {
		return processId;
	}

	/**
	 * @param processId the processId to set
	 */
	public void setProcessId(int processId) {
		this.processId = processId;
	}

	/**
	 * @return the threadId
	 */
	public int getThreadId() {
		return threadId;
	}

	/**
	 * @param threadId the threadId to set
	 */
	public void setThreadId(int threadId) {
		this.threadId = threadId;
	}

	/**
	 * @return the exceptionCode
	 */
	public int getExceptionCode() {
		return exceptionCode;
	}

	/**
	 * @param exceptionCode the exceptionCode to set
	 */
	public void setExceptionCode(int exceptionCode) {
		this.exceptionCode = exceptionCode;
	}

	/**
	 * @return the exceptionAddress
	 */
	public long getExceptionAddress() {
		return exceptionAddress;
	}

	/**
	 * @param exceptionAddress the exceptionAddress to set
	 */
	public void setExceptionAddress(long exceptionAddress) {
		this.exceptionAddress = exceptionAddress;
	}

	/**
	 * @return the eventCode
	 */
	public int getEventCode() {
		return eventCode;
	}

	/**
	 * @param eventCode the eventCode to set
	 */
	public void setEventCode(int eventCode) {
		this.eventCode = eventCode;
	}

	public int getExceptionFlags() {
		return exceptionFlags;
	}

	public void setExceptionFlags(int exceptionFlags) {
		this.exceptionFlags = exceptionFlags;
	}

	public long getExceptionRecord() {
		return exceptionRecord;
	}

	public void setExceptionRecord(long exceptionRecord) {
		this.exceptionRecord = exceptionRecord;
	}

}
