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
import java.util.ArrayList;
import java.util.List;

import generic.stl.Pair;
import ghidra.app.util.bin.StructConverter;
import ghidra.file.formats.dump.DumpFileReader;
import ghidra.program.model.data.*;

public class PagedumpFileHeader implements StructConverter {

	public final static String NAME = "PAGEDUMP_HEADER";

	public final static int HEADER_SIZE = 0x1000;
	public final static int DMP_PHYSICAL_MEMORY_BLOCK_SIZE_32 = 700;
	public final static int DMP_PHYSICAL_MEMORY_BLOCK_SIZE_64 = 700;
	public final static int DMP_CONTEXT_RECORD_SIZE_32 = 1200;
	public final static int DMP_CONTEXT_RECORD_SIZE_64 = 3000;
	public final static int DMP_HEADER_COMMENT_SIZE = 128;
	public final static int DMP_RESERVED_0_SIZE_32 = 1760;
	public final static int DMP_RESERVED_2_SIZE_32 = 16;
	public final static int DMP_RESERVED_3_SIZE_32 = 56;
	public final static int DMP_RESERVED_0_SIZE_64 = 4008;

	public static int OFFSET_DUMP_TYPE = 0xF88;

	private int signature;
	private int validDump;
	private int majorVersion;
	private int minorVersion;
	private long directoryTableBase;
	private long pfnTableBase;
	private long psLoadedModuleList;
	private long psActiveProcessHead;
	private int machineImageType;
	private int numberOfProcessors;
	private int bugCheckCode;
	private long bugCheckParameter1;
	private long bugCheckParameter2;
	private long bugCheckParameter3;
	private long bugCheckParameter4;
	private byte[] versionUser = new byte[0x20];
	private long kdDebuggerDataBlock;
	protected PhysicalMemoryDescriptor pmd;

	private int dumpType;
	private int miniDumpFields;
	private int secondaryDataState;
	private int productType;
	private int suiteMask;
	private int writerStatus;
	private int paeEnabled;
	private int kdSecondaryVersion;
	private int attributes;
	private int bootId;
	private long requiredDumpSpace;
	private long systemUpTime;
	private long systemTime;

	protected List<Pair<Integer, DataType>> delayedAdds = new ArrayList<Pair<Integer, DataType>>();

	protected DumpFileReader reader;
	protected long index;
	private Pagedump pd;
	private int psz;
	private int pad = Pagedump.SIGNATURE;    // "PAGE"
	private int padSize = 4;
	private boolean is32Bit;

	private long contextOffset;

	PagedumpFileHeader(DumpFileReader reader, long index, Pagedump pd) throws IOException {
		this.reader = reader;
		this.index = index;
		this.pd = pd;
		this.psz = reader.getPointerSize();
		is32Bit = psz == 4;

		parse();
	}

	PagedumpFileHeader(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parseLight();
	}

	private void parseLight() throws IOException {
		reader.setPointerIndex(index);

		setSignature(reader.readNextInt());
		setValidDump(reader.readNextInt());

		int valid = getValidDump();
		psz = (valid == Pagedump.SIG_VALID1) ? 32 : 64;
		reader.setPointerSize(psz);

		setMajorVersion(reader.readNextInt());
		setMinorVersion(reader.readNextInt());
		setDirectoryTableBase(reader.readNextPointer());
		setPfnTableBase(reader.readNextPointer());
		setPsLoadedModuleList(reader.readNextPointer());
		setPsActiveProcessHead(reader.readNextPointer());
		setMachineImageType(reader.readNextInt());
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setSignature(reader.readNextInt());
		setValidDump(reader.readNextInt());
		setMajorVersion(reader.readNextInt());
		setMinorVersion(reader.readNextInt());
		setDirectoryTableBase(reader.readNextPointer());
		setPfnTableBase(reader.readNextPointer());
		setPsLoadedModuleList(reader.readNextPointer());
		setPsActiveProcessHead(reader.readNextPointer());
		setMachineImageType(reader.readNextInt());
		setNumberOfProcessors(reader.readNextInt());
		setBugCheckCode(reader.readNextInt());
		reader.readNextInt();
		setBugCheckParameter1(reader.readNextPointer());
		setBugCheckParameter2(reader.readNextPointer());
		setBugCheckParameter3(reader.readNextPointer());
		setBugCheckParameter4(reader.readNextPointer());
		for (int i = 0; i < versionUser.length; i++) {
			versionUser[i] = reader.readNextByte();
		}
		if (is32Bit()) {
			setPaeEnabled(reader.readNextByte());
			setKdSecondaryVersion(reader.readNextByte());
			reader.readNextByte();
			reader.readNextByte();
		}
		setKdDebuggerDataBlock(reader.readNextPointer());
		long offsetPMD = reader.getPointerIndex();
		long pmdSize =
			is32Bit() ? DMP_PHYSICAL_MEMORY_BLOCK_SIZE_32 : DMP_PHYSICAL_MEMORY_BLOCK_SIZE_64;
		long ctxtSize = is32Bit() ? DMP_CONTEXT_RECORD_SIZE_32 : DMP_CONTEXT_RECORD_SIZE_64;
		long offset = offsetPMD + pmdSize + padSize + ctxtSize;

		CategoryPath path = new CategoryPath("/winnt.h");
		DataType dt =
			pd.getTypeFromArchive(path, is32Bit() ? "EXCEPTION_RECORD32" : "EXCEPTION_RECORD64");
		if (dt != null) {
			offset += dt.getLength();
		}
		else {
			offset += is32Bit() ? 0x54 : 0x98; // ExceptionRecord
		}

		if (is32Bit()) {
			offset += DMP_HEADER_COMMENT_SIZE;
			reader.setPointerIndex(offset);
			int val = reader.readNextInt();
			if (val != pad) {
				setAttributes(val);
			}
			val = reader.readNextInt();
			if (val != pad) {
				setAttributes(val);
			}
			offset = reader.getPointerIndex();
			offset += DMP_CONTEXT_RECORD_SIZE_32;
		}

		reader.setPointerIndex(offset);
		OFFSET_DUMP_TYPE = (int) offset;
		setDumpType(reader.readNextInt());
		reader.readNextInt();  // pad

		if (!is32Bit()) {
			setRequiredDumpSpace(reader.readNextLong());
			setSystemTime(reader.readNextLong());
			for (int i = 0; i < DMP_HEADER_COMMENT_SIZE; i++) {
				reader.readNextByte();
			}
			setSystemUpTime(reader.readNextLong());
		}

		int val = reader.readNextInt();
		if (val != pad) {
			setMiniDumpFields(val);
		}
		val = reader.readNextInt();
		if (val != pad) {
			setSecondaryDataState(val);
		}
		val = reader.readNextInt();
		if (val != pad) {
			setProductType(val);
		}
		val = reader.readNextInt();
		if (val != pad) {
			setSuiteMask(val);
		}
		val = reader.readNextInt();
		if (val != pad) {
			setWriterStatus(val);
		}

		if (is32Bit()) {
			setRequiredDumpSpace(reader.readNextLong());
			for (int i = 0; i < DMP_RESERVED_0_SIZE_32; i++) {
				reader.readNextByte();
			}
			setSystemUpTime(reader.readNextLong());
			setSystemTime(reader.readNextLong());
			for (int i = 0; i < DMP_RESERVED_0_SIZE_32; i++) {
				reader.readNextByte();
			}
		}
		else {
			val = reader.readNextInt();
			if (val != pad) {
				setKdSecondaryVersion(val);
			}
			val = reader.readNextInt();
			if (val != pad) {
				setAttributes(val);
			}
			val = reader.readNextInt();
			if (val != pad) {
				setBootId(val);
			}
			for (int i = 0; i < DMP_RESERVED_0_SIZE_64; i++) {
				reader.readNextByte();
			}
		}

		if (dumpType != Pagedump.DUMP_TYPE_TRIAGE ||
			(miniDumpFields & Pagedump.TRIAGE_DUMP_DATA_BLOCKS) > 0) {
			val = reader.readInt(offsetPMD);
			if (val != pad) {
				pmd = new PhysicalMemoryDescriptor(reader, offsetPMD);
			}
		}

	}

	public long getContextOffset() {
		return contextOffset;
	}

	@Override
	public DataType toDataType() {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(STRING, 4, "Signature", null);
		struct.add(STRING, 4, "ValidDump", null);
		struct.add(DWORD, 4, "MajorVersion", null);
		struct.add(DWORD, 4, "MinorVersion", null);
		struct.add(POINTER, psz, "DirectoryTableBase", null);
		struct.add(POINTER, psz, "PfnTableBase", null);
		struct.add(POINTER, psz, "PsLoadedModuleList", null);
		struct.add(POINTER, psz, "PsActiveProcessHead", null);
		struct.add(DWORD, 4, "MachineImageType", null);
		struct.add(DWORD, 4, "NumberOfProcessors", null);
		struct.add(DWORD, 4, "BugCheckCode", null);
		struct.add(STRING, 4, "__unusedAlignment", null);
		struct.add(POINTER, psz, "BugCheckParameter1", null);
		struct.add(POINTER, psz, "BugCheckParameter2", null);
		struct.add(POINTER, psz, "BugCheckParameter3", null);
		struct.add(POINTER, psz, "BugCheckParameter4", null);
		struct.add(STRING, versionUser.length, "VersionUser", null);
		if (is32Bit()) {
			struct.add(BYTE, 1, "PaeEnabled", null);
			struct.add(BYTE, 1, "KdSecondaryVersion", null);
			struct.add(BYTE, 1, "", null);
			struct.add(BYTE, 1, "", null);
		}
		struct.add(POINTER, psz, "KdDebuggerDataBlock", null);

		long pmdSize =
			is32Bit() ? DMP_PHYSICAL_MEMORY_BLOCK_SIZE_32 : DMP_PHYSICAL_MEMORY_BLOCK_SIZE_64;
		struct.add(STRING, (int) pmdSize, "PhysicalMemoryBlock", null);
		struct.add(STRING, 4, "__unusedAlignment", null);

		CategoryPath path = new CategoryPath("/winnt.h");
		long ctxtSize = is32Bit() ? DMP_CONTEXT_RECORD_SIZE_32 : DMP_CONTEXT_RECORD_SIZE_64;
		DataType dt = pd.getTypeFromArchive(path, "CONTEXT");
		if (dt != null) {
			contextOffset = struct.getLength();
			struct.add(dt, dt.getLength(), "ContextRecord", null);
			struct.add(STRING, (int) ctxtSize - dt.getLength(), "__unusedAlignment", null);
		}

		dt = pd.getTypeFromArchive(path, is32Bit() ? "EXCEPTION_RECORD32" : "EXCEPTION_RECORD64");
		if (dt != null) {
			struct.add(dt, dt.getLength(), "ExceptionRecord", null);
		}
		else {
			struct.add(DWORD, 4, "ExceptionCode", null);
			struct.add(DWORD, 4, "ExceptionFlags", null);
			struct.add(POINTER, psz, "ExceptionRecord", null);
			struct.add(POINTER, psz, "ExceptionAddress", null);
			struct.add(DWORD, 4, "NumberParameters", null);
			struct.add(STRING, 4, "__unusedAlignment", null);
			ArrayDataType eiDt = new ArrayDataType(POINTER, 15, psz);
			struct.add(eiDt, eiDt.getLength(), "ExceptionInformation", null);
		}

		if (is32Bit()) {
			struct.add(STRING, DMP_HEADER_COMMENT_SIZE, "Comment", null);
			dt = getAttributes() == 0 ? STRING : DWORD;
			struct.add(QWORD, 8, "Attributes", null);
			dt = getBootId() == 0 ? STRING : DWORD;
			struct.add(DWORD, 4, "BootId", null);
			struct.add(STRING, DMP_RESERVED_0_SIZE_32, "_reserved0", null);
		}

		struct.growStructure(OFFSET_DUMP_TYPE - struct.getLength());
		struct.add(DWORD, 4, "DumpType", null);
		struct.add(STRING, 4, "__unusedAlignment", null);

		if (!is32Bit()) {
			struct.add(QWORD, 8, "RequiredDumpSpace", null);
			struct.add(QWORD, 8, "SystemTime", null);
			struct.add(STRING, DMP_HEADER_COMMENT_SIZE, "Comment", null);
			struct.add(QWORD, 8, "SystemUpTime", null);
		}

		dt = miniDumpFields == 0 ? STRING : DWORD;
		struct.add(dt, 4, "MiniDumpFields", null);
		dt = secondaryDataState == 0 ? STRING : DWORD;
		struct.add(dt, 4, "SecondaryDataState", null);
		dt = productType == 0 ? STRING : DWORD;
		struct.add(dt, 4, "ProductType", null);
		dt = suiteMask == 0 ? STRING : DWORD;
		struct.add(dt, 4, "SuiteMask", null);
		dt = getWriterStatus() == 0 ? STRING : DWORD;
		struct.add(dt, 4, "WriterStatus", null);

		if (is32Bit()) {
			struct.add(QWORD, 8, "RequiredDumpSpace", null);
			struct.add(STRING, DMP_RESERVED_2_SIZE_32, "_reserved2", null);
			struct.add(QWORD, 8, "SystemUpTime", null);
			struct.add(QWORD, 8, "SystemTime", null);
			struct.add(STRING, DMP_RESERVED_3_SIZE_32, "_reserved3", null);
		}
		else {
			dt = getKdSecondaryVersion() == 0 ? STRING : DWORD;
			struct.add(dt, 4, "KdSecondaryVersion", null);
			dt = getAttributes() == 0 ? STRING : DWORD;
			struct.add(dt, 4, "Attributes", null);
			dt = getBootId() == 0 ? STRING : DWORD;
			struct.add(dt, 4, "BootId", null);
			struct.add(STRING, DMP_RESERVED_0_SIZE_64, "_reserved0", null);
		}

		//replace(struct, BYTE, OFFSET_PAE_ENABLED, "PaeEnabled");
		//if ((miniDumpFields & Pagedump.TRIAGE_DUMP_DATA_BLOCKS) > 0 && pmd.getNumberOfRuns() > 0) {
		/*
		struct.growStructure(HEADER_SIZE - struct.getLength());
		
		if (pmd != null && pmd.getNumberOfRuns() > 0) {
			replace(struct, pmd.toDataType(), OFFSET_PHYS_MEM, "PhysicalMemoryBlockBuffer");
		}
		
		for (Pair<Integer, DataType> pair : delayedAdds) {
			replace(struct, pair.second, pair.first, pair.second.getDisplayName());
		}
		*/

		struct.setCategoryPath(new CategoryPath("/PDMP"));

		return struct;
	}

	public void addToDataType(DataType dt, long offset) {
		delayedAdds.add(new Pair<Integer, DataType>((int) offset, dt));
	}

	public int getSignature() {
		return signature;
	}

	public void setSignature(int signature) {
		this.signature = signature;
	}

	public int getValidDump() {
		return validDump;
	}

	public void setValidDump(int validDump) {
		this.validDump = validDump;
	}

	public int getMajorVersion() {
		return majorVersion;
	}

	public void setMajorVersion(int majorVersion) {
		this.majorVersion = majorVersion;
	}

	public int getMinorVersion() {
		return minorVersion;
	}

	public void setMinorVersion(int minorVersion) {
		this.minorVersion = minorVersion;
	}

	public long getDirectoryTableBase() {
		return directoryTableBase;
	}

	public void setDirectoryTableBase(long directoryTableBase) {
		this.directoryTableBase = directoryTableBase;
	}

	public long getPfnTableBase() {
		return pfnTableBase;
	}

	public void setPfnTableBase(long pfnTableBase) {
		this.pfnTableBase = pfnTableBase;
	}

	public long getPsLoadedModuleList() {
		return psLoadedModuleList;
	}

	public void setPsLoadedModuleList(long psLoadedModuleList) {
		this.psLoadedModuleList = psLoadedModuleList;
	}

	public long getPsActiveProcessHead() {
		return psActiveProcessHead;
	}

	public void setPsActiveProcessHead(long psActiveProcessHead) {
		this.psActiveProcessHead = psActiveProcessHead;
	}

	public int getMachineImageType() {
		return machineImageType;
	}

	public void setMachineImageType(int machineImageType) {
		this.machineImageType = machineImageType;
	}

	public int getNumberOfProcessors() {
		return numberOfProcessors;
	}

	public void setNumberOfProcessors(int numberOfProcessors) {
		this.numberOfProcessors = numberOfProcessors;
	}

	public PhysicalMemoryDescriptor getPhysicalMemoryBlockBuffer() {
		return pmd;
	}

	public void setPhysicalMemoryBlockBuffer(PhysicalMemoryDescriptor pmd) {
		this.pmd = pmd;
	}

	public int getDumpType() {
		return dumpType;
	}

	public void setDumpType(int dumpType) {
		this.dumpType = dumpType;
	}

	public long getRequiredDumpSpace() {
		return requiredDumpSpace;
	}

	public void setRequiredDumpSpace(long requiredDumpSpace) {
		this.requiredDumpSpace = requiredDumpSpace;
	}

	public long getSystemUpTime() {
		return systemUpTime;
	}

	public void setSystemUpTime(long systemUpTime) {
		this.systemUpTime = systemUpTime;
	}

	public long getSystemTime() {
		return systemTime;
	}

	public void setSystemTime(long systemTime) {
		this.systemTime = systemTime;
	}

	public int getBugCheckCode() {
		return bugCheckCode;
	}

	public void setBugCheckCode(int bugCheckCode) {
		this.bugCheckCode = bugCheckCode;
	}

	public long getBugCheckParameter1() {
		return bugCheckParameter1;
	}

	public void setBugCheckParameter1(long bugCheckParameter1) {
		this.bugCheckParameter1 = bugCheckParameter1;
	}

	public long getBugCheckParameter2() {
		return bugCheckParameter2;
	}

	public void setBugCheckParameter2(long bugCheckParameter2) {
		this.bugCheckParameter2 = bugCheckParameter2;
	}

	public long getBugCheckParameter3() {
		return bugCheckParameter3;
	}

	public void setBugCheckParameter3(long bugCheckParameter3) {
		this.bugCheckParameter3 = bugCheckParameter3;
	}

	public long getBugCheckParameter4() {
		return bugCheckParameter4;
	}

	public void setBugCheckParameter4(long bugCheckParameter4) {
		this.bugCheckParameter4 = bugCheckParameter4;
	}

	public long getKdDebuggerDataBlock() {
		return kdDebuggerDataBlock;
	}

	public void setKdDebuggerDataBlock(long kdDebuggerDataBlock) {
		this.kdDebuggerDataBlock = kdDebuggerDataBlock;
	}

	public int getMiniDumpFields() {
		return miniDumpFields;
	}

	public void setMiniDumpFields(int miniDumpFields) {
		this.miniDumpFields = miniDumpFields;
	}

	public int getSecondaryDataState() {
		return secondaryDataState;
	}

	public void setSecondaryDataState(int secondaryDataState) {
		this.secondaryDataState = secondaryDataState;
	}

	public int getProductType() {
		return productType;
	}

	public void setProductType(int productType) {
		this.productType = productType;
	}

	public int getSuiteMask() {
		return suiteMask;
	}

	public void setSuiteMask(int suiteMask) {
		this.suiteMask = suiteMask;
	}

	public int getWriterStatus() {
		return writerStatus;
	}

	public void setWriterStatus(int writerStatus) {
		this.writerStatus = writerStatus;
	}

	public int getKdSecondaryVersion() {
		return kdSecondaryVersion;
	}

	public void setKdSecondaryVersion(int kdSecondaryVersion) {
		this.kdSecondaryVersion = kdSecondaryVersion;
	}

	public int getAttributes() {
		return attributes;
	}

	public void setAttributes(int attributes) {
		this.attributes = attributes;
	}

	public int getBootId() {
		return bootId;
	}

	public void setBootId(int bootId) {
		this.bootId = bootId;
	}

	public boolean is32Bit() {
		return is32Bit;
	}

	public int getPaeEnabled() {
		return paeEnabled;
	}

	public void setPaeEnabled(int paeEnabled) {
		this.paeEnabled = paeEnabled;
	}

}
