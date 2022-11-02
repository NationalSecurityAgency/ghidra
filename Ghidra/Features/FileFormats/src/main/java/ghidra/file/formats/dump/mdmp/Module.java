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

public class Module implements StructConverter {

	public final static String NAME = "MINIDUMP_MODULE";

	private long baseOfImage;
	private int sizeOfImage;
	private int checkSum;
	private int timeDateStamp;
	private int moduleNameRVA;

	private int dwSignature; /* e.g. 0xfeef04bd */
	private int dwStrucVersion; /* e.g. 0x00000042 = "0.42" */
	private int dwFileVersionMS; /* e.g. 0x00030075 = "3.75" */
	private int dwFileVersionLS; /* e.g. 0x00000031 = "0.31" */
	private int dwProductVersionMS; /* e.g. 0x00030010 = "3.10" */
	private int dwProductVersionLS; /* e.g. 0x00000031 = "0.31" */
	private int dwFileFlagsMask; /* = 0x3F for version "0.42" */
	private int dwFileFlags; /* e.g. VFF_DEBUG | VFF_PRERELEASE */
	private int dwFileOS; /* e.g. VOS_DOS_WINDOWS16 */
	private int dwFileType; /* e.g. VFT_DRIVER */
	private int dwFileSubtype; /* e.g. VFT2_DRV_KEYBOARD */
	private int dwFileDateMS; /* e.g. 0 */
	private int dwFileDateLS; /* e.g. 0 */

	private int cvRecordDataSize;
	private int cvRecordRVA;
	private int miscRecordDataSize;
	private int miscRecordRVA;

	private int moduleNameLength;
	private String moduleName;
	private CvRecord cvRecord;

	private DumpFileReader reader;
	private long index;

	Module(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
		getRVAs();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setBaseOfImage(reader.readNextLong());
		setSizeOfImage(reader.readNextInt());
		setCheckSum(reader.readNextInt());
		setTimeDateStamp(reader.readNextInt());
		setModuleNameRVA(reader.readNextInt());

		setDwSignature(reader.readNextInt());
		setDwStrucVersion(reader.readNextInt());
		setDwFileVersionMS(reader.readNextInt());
		setDwFileVersionLS(reader.readNextInt());
		setDwProductVersionMS(reader.readNextInt());
		setDwProductVersionLS(reader.readNextInt());
		setDwFileFlagsMask(reader.readNextInt());
		setDwFileFlags(reader.readNextInt());
		setDwFileOS(reader.readNextInt());
		setDwFileType(reader.readNextInt());
		setDwFileSubtype(reader.readNextInt());
		setDwFileDateMS(reader.readNextInt());
		setDwFileDateLS(reader.readNextInt());

		setCvRecordDataSize(reader.readNextInt());
		setCvRecordRVA(reader.readNextInt());
		setMiscRecordDataSize(reader.readNextInt());
		setMiscRecordRVA(reader.readNextInt());

		reader.readNextLong();
		reader.readNextLong();
	}

	private void getRVAs() throws IOException {
		long pos = reader.getPointerIndex();

		reader.setPointerIndex(getModuleNameRVA());
		moduleNameLength = reader.readNextInt();
		moduleName = reader.readNextUnicodeString();

		cvRecord = new CvRecord(reader, getCvRecordRVA());

		reader.setPointerIndex(pos);
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

		StructureDataType sv = new StructureDataType("VersionInfo", 0);
		sv.add(DWORD, 4, "Signature", null);
		sv.add(DWORD, 4, "StrucVersion", null);
		sv.add(DWORD, 4, "FileVersionMS", null);
		sv.add(DWORD, 4, "FileVersionLS", null);
		sv.add(DWORD, 4, "ProductVersionMS", null);
		sv.add(DWORD, 4, "ProductVersionLS", null);
		sv.add(DWORD, 4, "FileFlagsMask", null);
		sv.add(DWORD, 4, "FileFlags", null);
		sv.add(DWORD, 4, "FileOS", null);
		sv.add(DWORD, 4, "FileType", null);
		sv.add(DWORD, 4, "FileSubtype", null);
		sv.add(DWORD, 4, "FileDateMS", null);
		sv.add(DWORD, 4, "FileDateLS", null);

		StructureDataType s0 = new StructureDataType("CvRecord", 0);
		s0.add(DWORD, 4, "DataSize", null);
		s0.add(Pointer32DataType.dataType, 4, "RVA", null);

		StructureDataType s1 = new StructureDataType("MiscRecord", 0);
		s1.add(DWORD, 4, "DataSize", null);
		s1.add(Pointer32DataType.dataType, 4, "RVA", null);

		struct.add(sv, sv.getLength(), sv.getDisplayName(), null);
		struct.add(s0, s0.getLength(), s0.getDisplayName(), null);
		struct.add(s1, s1.getLength(), s1.getDisplayName(), null);
		struct.add(QWORD, 8, "Reserved0", null);
		struct.add(QWORD, 8, "Reserved1", null);

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

	public int getDwSignature() {
		return dwSignature;
	}

	public void setDwSignature(int dwSignature) {
		this.dwSignature = dwSignature;
	}

	public int getDwStrucVersion() {
		return dwStrucVersion;
	}

	public void setDwStrucVersion(int dwStrucVersion) {
		this.dwStrucVersion = dwStrucVersion;
	}

	public int getDwFileVersionMS() {
		return dwFileVersionMS;
	}

	public void setDwFileVersionMS(int dwFileVersionMS) {
		this.dwFileVersionMS = dwFileVersionMS;
	}

	public int getDwFileVersionLS() {
		return dwFileVersionLS;
	}

	public void setDwFileVersionLS(int dwFileVersionLS) {
		this.dwFileVersionLS = dwFileVersionLS;
	}

	public int getDwProductVersionMS() {
		return dwProductVersionMS;
	}

	public void setDwProductVersionMS(int dwProductVersionMS) {
		this.dwProductVersionMS = dwProductVersionMS;
	}

	public int getDwProductVersionLS() {
		return dwProductVersionLS;
	}

	public void setDwProductVersionLS(int dwProductVersionLS) {
		this.dwProductVersionLS = dwProductVersionLS;
	}

	public int getDwFileFlagsMask() {
		return dwFileFlagsMask;
	}

	public void setDwFileFlagsMask(int dwFileFlagsMask) {
		this.dwFileFlagsMask = dwFileFlagsMask;
	}

	public int getDwFileFlags() {
		return dwFileFlags;
	}

	public void setDwFileFlags(int dwFileFlags) {
		this.dwFileFlags = dwFileFlags;
	}

	public int getDwFileOS() {
		return dwFileOS;
	}

	public void setDwFileOS(int dwFileOS) {
		this.dwFileOS = dwFileOS;
	}

	public int getDwFileType() {
		return dwFileType;
	}

	public void setDwFileType(int dwFileType) {
		this.dwFileType = dwFileType;
	}

	public int getDwFileSubtype() {
		return dwFileSubtype;
	}

	public void setDwFileSubtype(int dwFileSubtype) {
		this.dwFileSubtype = dwFileSubtype;
	}

	public int getDwFileDateMS() {
		return dwFileDateMS;
	}

	public void setDwFileDateMS(int dwFileDateMS) {
		this.dwFileDateMS = dwFileDateMS;
	}

	public int getDwFileDateLS() {
		return dwFileDateLS;
	}

	public void setDwFileDateLS(int dwFileDateLS) {
		this.dwFileDateLS = dwFileDateLS;
	}

	public int getCvRecordDataSize() {
		return cvRecordDataSize;
	}

	public void setCvRecordDataSize(int cvRecordDataSize) {
		this.cvRecordDataSize = cvRecordDataSize;
	}

	public int getCvRecordRVA() {
		return cvRecordRVA;
	}

	public void setCvRecordRVA(int cvRecordRVA) {
		this.cvRecordRVA = cvRecordRVA;
	}

	public int getMiscRecordDataSize() {
		return miscRecordDataSize;
	}

	public void setMiscRecordDataSize(int miscRecordDataSize) {
		this.miscRecordDataSize = miscRecordDataSize;
	}

	public int getMiscRecordRVA() {
		return miscRecordRVA;
	}

	public void setMiscRecordRVA(int miscRecordRVA) {
		this.miscRecordRVA = miscRecordRVA;
	}

	public int getModuleNameLength() {
		return moduleNameLength;
	}

	public String getModuleName() {
		return moduleName;
	}

	public CvRecord getCvRecord() {
		return cvRecord;
	}

}
