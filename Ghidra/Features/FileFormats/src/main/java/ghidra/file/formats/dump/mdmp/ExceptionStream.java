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

public class ExceptionStream implements StructConverter {

	public final static String NAME = "MINIDUMP_EXCEPTION";
	public final static int EXCEPTION_MAXIMUM_PARAMETERS = 15;

	private int threadId;
	private int exceptionCode;
	private int exceptionFlags;
	private long exceptionRecord;
	private long exceptionAddress;
	private int numberOfParameters;
	private long[] exceptionInformation;
	private int contextDataSize;
	private int contextRVA;

	private StructureDataType defaultContext;
	private String[] keys1 = { "ContextFlags", "DR0", "DR1", "DR2", "DR3", "DR6", "DR7" };
	private String[] keys2 = { "GS", "FS", "ES", "DS", "EDI", "ESI", "EBX", "EDX", "ECX", "EAX",
		"EBP", "EIP", "CS", "eflags", "ESP", "SS" };

	private DumpFileReader reader;
	private long index;

	ExceptionStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
		getRVAs();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setThreadId(reader.readNextInt());
		reader.readNextInt();
		setExceptionCode(reader.readNextInt());
		setExceptionFlags(reader.readNextInt());
		setExceptionRecord(reader.readNextLong());
		setExceptionAddress(reader.readNextLong());

		setNumberOfParameters(reader.readNextInt());
		reader.readNextInt();
		exceptionInformation = new long[EXCEPTION_MAXIMUM_PARAMETERS];
		for (int i = 0; i < EXCEPTION_MAXIMUM_PARAMETERS; i++) {
			setExceptionInformation(reader.readNextLong(), i);
		}

		setContextDataSize(reader.readNextInt());
		setContextRVA(reader.readNextInt());

	}

	private void getRVAs() {
		long pos = reader.getPointerIndex();

		reader.setPointerIndex(getContextRVA());

		defaultContext =
			new StructureDataType("ExceptionContext_" + Integer.toHexString(threadId), 0);
		for (int i = 0; i < 7; i++) {
			defaultContext.add(DWORD, keys1[i], null);
		}
		for (int i = 7; i < 35; i++) {
			defaultContext.add(DWORD, "", null);
		}
		for (int i = 35; i < 51; i++) {
			defaultContext.add(DWORD, keys2[i - 35], null);
		}
		for (int i = 51; i < 179 && i < getContextDataSize() / 4; i++) {
			defaultContext.add(DWORD, "", null);
		}

		reader.setPointerIndex(pos);
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "ThreadId", null);

		StructureDataType s0 = new StructureDataType("ExceptionRecord", 0);
		s0.add(DWORD, 4, "__alignment", null);
		s0.add(DWORD, 4, "ExceptionCode", null);
		s0.add(DWORD, 4, "ExceptionFlags", null);
		s0.add(QWORD, 8, "ExceptionRecord", null);
		s0.add(QWORD, 8, "ExceptionAddress", null);
		s0.add(DWORD, 4, "NumberParameters", null);
		s0.add(DWORD, 4, "__unusedAlignment", null);

		ArrayDataType a = new ArrayDataType(QWORD, EXCEPTION_MAXIMUM_PARAMETERS, 8);
		s0.add(a, a.getLength(), "ExceptionInformation", null);

		StructureDataType s1 = new StructureDataType("ThreadContext", 0);
		s1.add(DWORD, 4, "DataSize", null);
		s1.add(Pointer32DataType.dataType, 4, "RVA", null);

		struct.add(s0, s0.getLength(), s0.getDisplayName(), null);
		struct.add(s1, s1.getLength(), s1.getDisplayName(), null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public void setThreadId(int threadId) {
		this.threadId = threadId;
	}

	public int getThreadId() {
		return threadId;
	}

	public int getExceptionCode() {
		return exceptionCode;
	}

	public void setExceptionCode(int exceptionCode) {
		this.exceptionCode = exceptionCode;
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

	public long getExceptionAddress() {
		return exceptionAddress;
	}

	public void setExceptionAddress(long exceptionAddress) {
		this.exceptionAddress = exceptionAddress;
	}

	public int getNumberOfParameters() {
		return numberOfParameters;
	}

	public void setNumberOfParameters(int numberOfParameters) {
		this.numberOfParameters = numberOfParameters;
	}

	public long getExceptionInformation(int idx) {
		return exceptionInformation[idx];
	}

	public void setExceptionInformation(long exceptionInformation, int index) {
		this.exceptionInformation[index] = exceptionInformation;
	}

	public void setContextDataSize(int contextDataSize) {
		this.contextDataSize = contextDataSize;
	}

	public int getContextDataSize() {
		return contextDataSize;
	}

	public void setContextRVA(int contextRVA) {
		this.contextRVA = contextRVA;
	}

	public int getContextRVA() {
		return contextRVA;
	}

	public StructureDataType getDefaultContext() {
		return defaultContext;
	}
}
