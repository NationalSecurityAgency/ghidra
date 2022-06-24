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

public class CvRecord implements StructConverter {

	public final static String NAME = "MINIDUMP_CV_RECORD";

	private int pdbFormat;
	private byte[] pdbSigGUID = new byte[16];
	private int pdbAge;
	private byte[] pdbName;

	private DumpFileReader reader;
	private long index;

	private int nameLength;

	CvRecord(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setPdbFormat(reader.readNextInt());
		for (int i = 0; i < pdbSigGUID.length; i++) {
			setPdbSigGUID(reader.readNextByte(), i);
		}
		setPdbAge(reader.readNextInt());
		nameLength = getNameLength(reader, reader.getPointerIndex());
		pdbName = new byte[nameLength];
		for (int i = 0; i < nameLength; i++) {
			setPdbName(reader.readNextByte(), i);
		}

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "PdbFormat", null);
		ArrayDataType adt = new ArrayDataType(BYTE, 16, 1);
		struct.add(adt, 16, "PdbSigGUID", null);
		struct.add(DWORD, 4, "PdbAge", null);
		//struct.add(STRING,nameLength,"PdbName",null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public int getPdbFormat() {
		return pdbFormat;
	}

	public void setPdbFormat(int pdbFormat) {
		this.pdbFormat = pdbFormat;
	}

	public byte[] getPdbSigGUID() {
		return pdbSigGUID;
	}

	public void setPdbSigGUID(byte b, int index) {
		this.pdbSigGUID[index] = b;
	}

	public int getPdbAge() {
		return pdbAge;
	}

	public void setPdbAge(int pdbAge) {
		this.pdbAge = pdbAge;
	}

	public byte[] getPdbName() {
		return pdbName;
	}

	public void setPdbName(byte b, int index) {
		this.pdbName[index] = b;
	}

	public static int getNameLength(DumpFileReader r, long pos) throws IOException {
		int i = 0;
		while (r.readNextByte() != 0)
			i++;
		r.setPointerIndex(pos);
		return i;
	}

}
