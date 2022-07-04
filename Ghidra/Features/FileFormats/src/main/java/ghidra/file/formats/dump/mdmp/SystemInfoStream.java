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

public class SystemInfoStream implements StructConverter {

	public final static String NAME = "MINIDUMP_SYSTEM_INFO";

	private short processorArchitecture;
	private short processorLevel;
	private short processorRevision;
	private byte numberOfProcessors;
	private byte productType;
	private int majorVersion;
	private int minorVersion;
	private int buildNumber;
	private int platformId;
	private int rva;
	private short suiteMask;
	private int[] vendorId = new int[3];
	private int versionInformation;
	private int featureInformation;
	private int AMDExtendedCpuFeatures;

	private int csdNameLength;
	private String csdName;

	private DumpFileReader reader;
	private long index;

	SystemInfoStream(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
		getRVAs();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setProcessorArchitecture(reader.readNextShort());
		setProcessorLevel(reader.readNextShort());
		setProcessorRevision(reader.readNextShort());
		setNumberOfProcessors(reader.readNextByte());
		setProductType(reader.readNextByte());
		setMajorVersion(reader.readNextInt());
		setMinorVersion(reader.readNextInt());
		setBuildNumber(reader.readNextInt());
		setPlatformId(reader.readNextInt());
		setCSDRevisionRVA(reader.readNextInt());
		setSuiteMask(reader.readNextShort());
		reader.readNextShort();

		for (int i = 0; i < 3; i++) {
			setVendorId(reader.readNextInt(), i);
		}
		setVersionInformation(reader.readNextInt());
		setFeatureInformation(reader.readNextInt());
		setAMDExtendedCpuFeatures(reader.readNextInt());

	}

	private void getRVAs() throws IOException {
		long pos = reader.getPointerIndex();

		reader.setPointerIndex(getCSDVersionRVA());
		csdNameLength = reader.readNextInt();
		csdName = reader.readNextUnicodeString();

		reader.setPointerIndex(pos);
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(WORD, 2, "ProcessorArchitecture", null);
		struct.add(WORD, 2, "ProcessorLevel", null);
		struct.add(WORD, 2, "ProcessorRevision", null);

		UnionDataType u0 = new UnionDataType(NAME + "_u0");
		u0.add(WORD, 2, "Reserved0", null);
		StructureDataType s0 = new StructureDataType(NAME + "_s0", 0);
		s0.add(BYTE, 1, "NumberOfProcessors", null);
		s0.add(BYTE, 1, "ProductType", null);
		u0.add(s0, 2, s0.getDisplayName(), null);
		struct.add(u0, u0.getLength(), u0.getDisplayName(), null);

		struct.add(DWORD, 4, "MajorVersion", null);
		struct.add(DWORD, 4, "MinorVersion", null);
		struct.add(DWORD, 4, "BuildNumber", null);
		struct.add(DWORD, 4, "PlatformId", null);
		struct.add(Pointer32DataType.dataType, 4, "CSDVersionRVA", null);

		UnionDataType u1 = new UnionDataType(NAME + "_u1");
		u1.add(DWORD, 4, "Reserved1", null);
		StructureDataType s1 = new StructureDataType(NAME + "_s1", 0);
		s1.add(WORD, 2, "SuiteMask", null);
		s1.add(WORD, 2, "Reserved1", null);
		u1.add(s1, 2, s1.getDisplayName(), null);
		struct.add(u1, u1.getLength(), u1.getDisplayName(), null);

		UnionDataType u2 = new UnionDataType("CPU_INFORMATION");
		StructureDataType s3 = new StructureDataType("X86CpuInfo", 0);

		ArrayDataType a0 = new ArrayDataType(DWORD, 3, 4);
		s3.add(a0, a0.getLength(), "VendorId", null);
		s3.add(DWORD, 4, "VersionInformation", null);
		s3.add(DWORD, 4, "FeatureInformation", null);
		s3.add(DWORD, 4, "AMDExtendedCpuFeatures", null);

		StructureDataType s4 = new StructureDataType("OtherCpuInfo", 0);
		ArrayDataType a1 = new ArrayDataType(QWORD, 2, 8);
		s4.add(a1, a1.getLength(), "ProcessorFeatures", null);

		u2.add(s3, s3.getLength(), s3.getDisplayName(), null);
		u2.add(s4, s4.getLength(), s4.getDisplayName(), null);
		struct.add(u2, u2.getLength(), u2.getDisplayName(), null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public short getProcessorArchitecture() {
		return processorArchitecture;
	}

	public void setProcessorArchitecture(short processorArchitecture) {
		this.processorArchitecture = processorArchitecture;
	}

	public short getProcessorLevel() {
		return processorLevel;
	}

	public void setProcessorLevel(short processorLevel) {
		this.processorLevel = processorLevel;
	}

	public short getProcessorRevision() {
		return processorRevision;
	}

	public void setProcessorRevision(short processorRevision) {
		this.processorRevision = processorRevision;
	}

	public byte getNumberOfProcessors() {
		return numberOfProcessors;
	}

	public void setNumberOfProcessors(byte numberOfProcessors) {
		this.numberOfProcessors = numberOfProcessors;
	}

	public byte getProductType() {
		return productType;
	}

	public void setProductType(byte productType) {
		this.productType = productType;
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

	public int getBuildNumber() {
		return buildNumber;
	}

	public void setBuildNumber(int buildNumber) {
		this.buildNumber = buildNumber;
	}

	public int getPlatformId() {
		return platformId;
	}

	public void setPlatformId(int platformId) {
		this.platformId = platformId;
	}

	public int getCSDVersionRVA() {
		return rva;
	}

	public void setCSDRevisionRVA(int rva) {
		this.rva = rva;
	}

	public short getSuiteMask() {
		return suiteMask;
	}

	public void setSuiteMask(short suiteMask) {
		this.suiteMask = suiteMask;
	}

	public int getVendorId(int idx) {
		return vendorId[idx];
	}

	public void setVendorId(int vendorId, int index) {
		this.vendorId[index] = vendorId;
	}

	public int getVersionInformation() {
		return versionInformation;
	}

	public void setVersionInformation(int versionInformation) {
		this.versionInformation = versionInformation;
	}

	public int getFeatureInformation() {
		return featureInformation;
	}

	public void setFeatureInformation(int featureInformation) {
		this.featureInformation = featureInformation;
	}

	public int getAMDExtendedCpuFeatures() {
		return AMDExtendedCpuFeatures;
	}

	public void setAMDExtendedCpuFeatures(int extendedCpuFeatures) {
		AMDExtendedCpuFeatures = extendedCpuFeatures;
	}

	public int getCSDNameLength() {
		return csdNameLength;
	}

	public String getCSDName() {
		return csdName;
	}
}
