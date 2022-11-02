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

public class FunctionTableStream implements StructConverter {

	public final static String NAME = "MINIDUMP_FUNCTION_TABLES";

	private int sizeOfHeader;
	private int sizeOfEntry;
	private int sizeOfNativeDescriptor;
	private int sizeOfFunctionEntry;
	private int numberOfDescriptors;
	private int sizeOfAlignPad;
	private FunctionTable[] descriptors;

	private DumpFileReader reader;
	private long index;

	FunctionTableStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setSizeOfHeader(reader.readNextInt());
		setSizeOfEntry(reader.readNextInt());
		setSizeOfNativeDescriptor(reader.readNextInt());
		setSizeOfFunctionEntry(reader.readNextInt());
		setNumberOfDescriptors(reader.readNextInt());
		setSizeOfAlignPad(reader.readNextInt());
		descriptors = new FunctionTable[numberOfDescriptors];
		for (int i = 0; i < numberOfDescriptors; i++) {
			setDescriptors(new FunctionTable(reader, reader.getPointerIndex()), i);
		}
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "SizeOfHeader", null);
		struct.add(DWORD, 4, "SizeOfDescriptor", null);
		struct.add(DWORD, 4, "SizeOfNativeDescriptor", null);
		struct.add(DWORD, 4, "SizeOfFunctionEntry", null);
		struct.add(DWORD, 4, "NumberOfDescriptors", null);
		struct.add(DWORD, 4, "SizeOfAlignPad", null);
		DataType t = descriptors[0].toDataType();
		ArrayDataType a = new ArrayDataType(t, numberOfDescriptors, t.getLength());
		struct.add(a, a.getLength(), "Descriptors", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public int getSizeOfHeader() {
		return sizeOfHeader;
	}

	public void setSizeOfHeader(int sizeOfHeader) {
		this.sizeOfHeader = sizeOfHeader;
	}

	public int getSizeOfEntry() {
		return sizeOfEntry;
	}

	public void setSizeOfEntry(int sizeOfEntry) {
		this.sizeOfEntry = sizeOfEntry;
	}

	public int getSizeOfNativeDescriptor() {
		return sizeOfNativeDescriptor;
	}

	public void setSizeOfNativeDescriptor(int sizeOfNativeDescriptor) {
		this.sizeOfNativeDescriptor = sizeOfNativeDescriptor;
	}

	public int getSizeOfFunctionEntry() {
		return sizeOfFunctionEntry;
	}

	public void setSizeOfFunctionEntry(int sizeOfFunctionEntry) {
		this.sizeOfFunctionEntry = sizeOfFunctionEntry;
	}

	public int getNumberOfDescriptors() {
		return numberOfDescriptors;
	}

	public void setNumberOfDescriptors(int numberOfDescriptors) {
		this.numberOfDescriptors = numberOfDescriptors;
	}

	public FunctionTable getDescriptors(int idx) {
		return descriptors[idx];
	}

	public void setDescriptors(FunctionTable descriptor, int index) {
		this.descriptors[index] = descriptor;
	}

	public void setSizeOfAlignPad(int sizeOfAlignPad) {
		this.sizeOfAlignPad = sizeOfAlignPad;
	}

	public int getSizeOfAlignPad() {
		return sizeOfAlignPad;
	}
}
