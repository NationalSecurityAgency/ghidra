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

public class MmPfn implements StructConverter {

	public final static String NAME = "PAGEDUMP_PHYS_MEM_RUN";

	private long pteAddress;
	private long origPte;
	private long blink;
	private long flags;
	private int parent;

	private DumpFileReader reader;
	private long index;
	private int psz;

	MmPfn(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		reader.readNextPointer();
		setPteAddress(reader.readNextPointer());
		setOrigPte(reader.readNextPointer());
		setBlink(reader.readNextPointer());
		setFlags(reader.readNextPointer());
		setParent(reader.readNextInt());
		reader.readNextInt();

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(QWORD, psz, "ListEntry", null);
		struct.add(QWORD, psz, "PteAddress", null);
		struct.add(QWORD, psz, "OriginalPte", null);
		struct.add(QWORD, psz, "", null);
		struct.add(QWORD, psz, "", null);
		struct.add(DWORD, 4, "Parent", null);
		struct.add(DWORD, 4, "", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public long getPteAddress() {
		return pteAddress;
	}

	public void setPteAddress(long pteAddress) {
		this.pteAddress = pteAddress;
	}

	public int getParent() {
		return parent;
	}

	public void setParent(int parent) {
		this.parent = parent;
	}

	public long getOrigPte() {
		return origPte;
	}

	public void setOrigPte(long origPte) {
		this.origPte = origPte;
	}

	public long getBlink() {
		return blink;
	}

	public void setBlink(long blink) {
		this.blink = blink;
	}

	public long getFlags() {
		return flags;
	}

	public void setFlags(long flags) {
		this.flags = flags;
	}

}
