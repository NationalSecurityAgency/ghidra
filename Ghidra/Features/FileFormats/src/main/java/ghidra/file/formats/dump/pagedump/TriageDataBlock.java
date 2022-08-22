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

public class TriageDataBlock implements StructConverter {

	public final static String NAME = "_TRIAGE_DATA_BLOCK";

	private long address;
	private int offset;
	private int size;

	private DumpFileReader reader;
	private long index;
	private int psz;

	TriageDataBlock(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setAddress(reader.readNextPointer());
		setOffset(reader.readNextInt());
		setSize(reader.readNextInt());

	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(POINTER, psz, "Address", null);
		struct.add(DWORD, 4, "Offset", null);
		struct.add(DWORD, 4, "Size", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public long getAddress() {
		return address;
	}

	public void setAddress(long address) {
		this.address = address;
	}

	public int getOffset() {
		return offset;
	}

	public void setOffset(int offset) {
		this.offset = offset;
	}

	public int getSize() {
		return size;
	}

	public void setSize(int size) {
		this.size = size;
	}

}
