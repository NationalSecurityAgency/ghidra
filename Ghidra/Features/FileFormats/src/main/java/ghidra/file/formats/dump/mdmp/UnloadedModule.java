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

public class UnloadedModule implements StructConverter {

	public final static String NAME = "MINIDUMP_UNLOADED_MODULE";

	private long baseOfImage;
	private int sizeOfImage;
	private int checkSum;
	private int timeDateStamp;
	private int moduleNameRVA;

	private DumpFileReader reader;
	private long index;

	UnloadedModule(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setBaseOfImage(reader.readNextLong());
		setSizeOfImage(reader.readNextInt());
		setCheckSum(reader.readNextInt());
		setTimeDateStamp(reader.readNextInt());
		setModuleNameRVA(reader.readNextInt());

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(QWORD, 8, "BaseOfImage", null);
		struct.add(DWORD, 4, "SizeOfImage", null);
		struct.add(DWORD, 4, "CheckSum", null);
		struct.add(DWORD, 4, "TimeDateStamp", null);
		struct.add(Pointer32DataType.dataType, 4, "ModuleNameRVA", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public long getBaseOfImage() {
		return baseOfImage;
	}

	public void setBaseOfImage(long baseOfImage) {
		this.baseOfImage = baseOfImage;
	}

	public int getSizeOfImage() {
		return sizeOfImage;
	}

	public void setSizeOfImage(int sizeOfImage) {
		this.sizeOfImage = sizeOfImage;
	}

	public int getCheckSum() {
		return checkSum;
	}

	public void setCheckSum(int checkSum) {
		this.checkSum = checkSum;
	}

	public int getTimeDateStamp() {
		return timeDateStamp;
	}

	public void setTimeDateStamp(int timeDateStamp) {
		this.timeDateStamp = timeDateStamp;
	}

	public int getModuleNameRVA() {
		return moduleNameRVA;
	}

	public void setModuleNameRVA(int moduleNameRVA) {
		this.moduleNameRVA = moduleNameRVA;
	}

}
