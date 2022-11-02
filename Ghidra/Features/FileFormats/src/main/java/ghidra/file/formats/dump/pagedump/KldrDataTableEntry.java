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

public class KldrDataTableEntry implements StructConverter {

	public final static String NAME = "_KLDR_DATA_TABLE_ENTRY";

	private long List_Flink;
	private long List_Blink;
	//private long __Undefined1;
	//private long __Undefined2;
	//private long __Undefined3;
	private long NonPagedDebugInfo;
	private long DllBase;
	private long EntryPoint;
	private int SizeOfImage;
	private long FullDllName;
	private long BaseDllName;
	private int Flags;
	private short LoadCount;
	//private short __Undefined5;
	//private long __Undefined6;
	private int CheckSum;
	//private int __padding1;
	private int TimeDateStamp;
	//private int __padding2;

	private DumpFileReader reader;
	private long index;
	private int psz;

	KldrDataTableEntry(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;
		this.psz = reader.getPointerSize();

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(getIndex());

		setList_Flink(reader.readNextPointer());
		setList_Blink(reader.readNextPointer());
		reader.readNextPointer();
		reader.readNextPointer();
		reader.readNextPointer();
		setNonPagedDebugInfo(reader.readNextPointer());
		setDllBase(reader.readNextPointer());
		setEntryPoint(reader.readNextPointer());
		setSizeOfImage(reader.readNextInt());
		reader.readNextInt();
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
		setTimeDateStamp(reader.readNextInt());
		reader.readNextInt();

	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(POINTER, psz, "List.Flink", null);
		struct.add(POINTER, psz, "List.Blink", null);
		struct.add(POINTER, psz, "__Undefined1", null);
		struct.add(POINTER, psz, "__Undefined2", null);
		struct.add(POINTER, psz, "__Undefined3", null);
		struct.add(POINTER, psz, "NonPagedDebugInfo", null);
		struct.add(POINTER, psz, "DllBase", null);
		struct.add(POINTER, psz, "EntryPoint", null);
		struct.add(DWORD, 4, "SizeOfImage", null);
		struct.add(DWORD, 4, "", null);
		struct.add(POINTER, psz, "FullDllNameLen", null);
		struct.add(POINTER, psz, "FullDllName", null);
		struct.add(POINTER, psz, "BaseDllNameLen", null);
		struct.add(POINTER, psz, "BaseDllName", null);
		struct.add(DWORD, 4, "Flags", null);
		struct.add(WORD, 2, "LoadCount", null);
		struct.add(WORD, 2, "__Undefined5", null);
		struct.add(POINTER, psz, "__Undefined6", null);
		struct.add(DWORD, 4, "CheckSum", null);
		struct.add(DWORD, 4, "__padding1", null);
		struct.add(DWORD, 4, "TimeDateStamp", null);
		struct.add(DWORD, 4, "__padding2", null);

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public long getList_Flink() {
		return List_Flink;
	}

	public void setList_Flink(long list_Flink) {
		List_Flink = list_Flink;
	}

	public long getList_Blink() {
		return List_Blink;
	}

	public void setList_Blink(long list_Blink) {
		List_Blink = list_Blink;
	}

	public long getDllBase() {
		return DllBase;
	}

	public void setDllBase(long dllBase) {
		DllBase = dllBase;
	}

	public long getEntryPoint() {
		return EntryPoint;
	}

	public void setEntryPoint(long entryPoint) {
		EntryPoint = entryPoint;
	}

	public int getSizeOfImage() {
		return SizeOfImage;
	}

	public void setSizeOfImage(int sizeOfImage) {
		SizeOfImage = sizeOfImage;
	}

	public long getFullDllName() {
		return FullDllName;
	}

	public void setFullDllName(long fullDllName) {
		FullDllName = fullDllName;
	}

	public long getBaseDllName() {
		return BaseDllName;
	}

	public void setBaseDllName(long baseDllName) {
		BaseDllName = baseDllName;
	}

	public int getFlags() {
		return Flags;
	}

	public void setFlags(int flags) {
		Flags = flags;
	}

	public short getLoadCount() {
		return LoadCount;
	}

	public void setLoadCount(short loadCount) {
		LoadCount = loadCount;
	}

	public int getCheckSum() {
		return CheckSum;
	}

	public void setCheckSum(int checkSum) {
		CheckSum = checkSum;
	}

	public int getTimeDateStamp() {
		return TimeDateStamp;
	}

	public void setTimeDateStamp(int timeDateStamp) {
		TimeDateStamp = timeDateStamp;
	}

	public long getNonPagedDebugInfo() {
		return NonPagedDebugInfo;
	}

	public void setNonPagedDebugInfo(long nonPagedDebugInfo) {
		NonPagedDebugInfo = nonPagedDebugInfo;
	}

	public String getName() {
		return "bob";
	}

	public long getIndex() {
		return index;
	}

}
