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
import ghidra.util.exception.DuplicateNameException;

public class ExceptionRecord implements StructConverter {

	public final static String NAME = "PAGEDUMP_EXCEPTION_RECORD";

	private int exceptionCode;
	private int exceptionFlags;
	private long exceptionRecord;
	private long exceptionAddress;
	private int numberOfParameters;

	private DumpFileReader reader;
	private long index;

	ExceptionRecord(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setExceptionCode(reader.readNextInt());
		setExceptionFlags(reader.readNextInt());
		setExceptionRecord(reader.readNextPointer());
		setExceptionAddress(reader.readNextPointer());
		setNumberOfParameters(reader.readNextInt());

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "ExceptionCode", null);
		struct.add(DWORD, 4, "ExceptionFlags", null);
		struct.add(DWORD, 4, "ExceptionRecord", null);
		struct.add(DWORD, 4, "ExceptionAddress", null);
		struct.add(DWORD, 4, "NumberOfParameters", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
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
}
