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

public class HandleDataStream implements StructConverter {

	public final static String NAME = "MINIDUMP_HANDLE_DATA";

	private int sizeOfHeader;
	private int sizeOfDescriptor;
	private int numberOfHandles;
	private Handle[] handles;

	private DumpFileReader reader;
	private long index;

	HandleDataStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setSizeOfHeader(reader.readNextInt());
		setSizeOfDescriptor(reader.readNextInt());
		setNumberOfHandles(reader.readNextInt());
		reader.readNextInt();
		handles = new Handle[numberOfHandles];
		for (int i = 0; i < numberOfHandles; i++) {
			setHandle(new Handle(reader, reader.getPointerIndex(), sizeOfDescriptor), i);
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "SizeOfHeader", null);
		struct.add(DWORD, 4, "SizeOfDescriptor", null);
		struct.add(DWORD, 4, "NumberOfHandles", null);
		struct.add(DWORD, 4, "Reserved", null);
		DataType t = handles[0].toDataType();
		ArrayDataType a = new ArrayDataType(t, numberOfHandles, t.getLength());
		struct.add(a, a.getLength(), "Handles", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public int getNumberOfHandles() {
		return numberOfHandles;
	}

	public void setNumberOfHandles(int numberOfHandles) {
		this.numberOfHandles = numberOfHandles;
	}

	public Handle getHandle(int idx) {
		return handles[idx];
	}

	public void setHandle(Handle handle, int index) {
		this.handles[index] = handle;
	}

	public void setSizeOfHeader(int sizeOfHeader) {
		this.sizeOfHeader = sizeOfHeader;
	}

	public int getSizeOfHeader() {
		return sizeOfHeader;
	}

	public void setSizeOfDescriptor(int sizeOfDescriptor) {
		this.sizeOfDescriptor = sizeOfDescriptor;
	}

	public int getSizeOfDescriptor() {
		return sizeOfDescriptor;
	}
}
