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

public class LoadedDriver implements StructConverter {

	public final static String NAME = "_KLDR_DATA_TABLE_ENTRY";

	private int nameOffset;
	private long dllBase;
	private long entryPoint;
	private long sizeOfImage;
	private long fullDllName;
	private long baseDllName;
	private int flags;
	private short loadCount;
	private int checkSum;
	private long buildFileHash;

	private DumpFileReader reader;
	private long index;
	private int psz;
	private boolean is32Bit;

	LoadedDriver(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();
		this.is32Bit = psz == 4;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setNameOffset(reader.readNextInt());
		int res0len = is32Bit ? 24 : 52;
		reader.readNextAsciiString(res0len);
		setDllBase(reader.readNextPointer());
		setEntryPoint(reader.readNextPointer());
		setSizeOfImage(reader.readNextPointer());
		reader.readNextPointer();
		setFullDllName(reader.readNextPointer());
		reader.readNextPointer();
		setBaseDllName(reader.readNextPointer());
		setFlags(reader.readNextInt());
		setLoadCount(reader.readNextShort());
		reader.readNextShort();
		reader.readNextPointer();
		setCheckSum(reader.readNextInt());
		reader.readNextInt();
		setBuildFileHash(reader.readNextInt());
		reader.readNextInt();
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(DWORD, 4, "NameOffset", null);
		struct.add(DWORD, 4, "", null);
		struct.add(POINTER, psz, "InLoadOrderLinks.Flink", null);
		struct.add(POINTER, psz, "InLoadOrderLinks.Blink", null);
		struct.add(POINTER, psz, "ExceptionTable", null);
		struct.add(POINTER, psz, "ExceptionTableSize", null);
		struct.add(POINTER, psz, "GpValue", null);
		struct.add(POINTER, psz, "NonPagedDebugInfo", null);
		struct.add(POINTER, psz, "DllBase", null);
		struct.add(POINTER, psz, "EntryPoint", null);
		struct.add(is32Bit ? DWORD : QWORD, psz, "SizeOfImage", null);
		struct.add(is32Bit ? DWORD : QWORD, psz, "", null);
		struct.add(POINTER, psz, "FullDllName", null);
		struct.add(is32Bit ? DWORD : QWORD, psz, "", null);
		struct.add(POINTER, psz, "BaseDllName", null);
		struct.add(DWORD, 4, "Flags", null);
		struct.add(WORD, 2, "LoadCount", null);
		struct.add(WORD, 2, "", null);
		struct.add(POINTER, psz, "SectionPointer", null);
		struct.add(is32Bit ? DWORD : QWORD, psz, "CheckSum", null);
		struct.add(is32Bit ? DWORD : QWORD, psz, "BuildFileHash", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public int getNameOffset() {
		return nameOffset;
	}

	public void setNameOffset(int nameOffset) {
		this.nameOffset = nameOffset;
	}

	public long getDllBase() {
		return dllBase;
	}

	public void setDllBase(long dllBase) {
		this.dllBase = dllBase;
	}

	public long getEntryPoint() {
		return entryPoint;
	}

	public void setEntryPoint(long entryPoint) {
		this.entryPoint = entryPoint;
	}

	public long getSizeOfImage() {
		return sizeOfImage;
	}

	public void setSizeOfImage(long sizeOfImage) {
		this.sizeOfImage = sizeOfImage;
	}

	public long getBuildFileHash() {
		return buildFileHash;
	}

	public void setBuildFileHash(long buildFileHash) {
		this.buildFileHash = buildFileHash;
	}

	public long getFullDllName() {
		return fullDllName;
	}

	public void setFullDllName(long fullDllName) {
		this.fullDllName = fullDllName;
	}

	public long getBaseDllName() {
		return baseDllName;
	}

	public void setBaseDllName(long baseDllName) {
		this.baseDllName = baseDllName;
	}

	public int getFlags() {
		return flags;
	}

	public void setFlags(int flags) {
		this.flags = flags;
	}

	public short getLoadCount() {
		return loadCount;
	}

	public void setLoadCount(short loadCount) {
		this.loadCount = loadCount;
	}

	public int getCheckSum() {
		return checkSum;
	}

	public void setCheckSum(int checkSum) {
		this.checkSum = checkSum;
	}

}
