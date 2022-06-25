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

public class MdmpFileHeader implements StructConverter {

	public final static String NAME = "MINIDUMP_HEADER";

	private int signature;
	private int version;
	private int numberOfStreams;
	private long streamDirectoryRVA;
	private int checkSum;
	private int timeDateStamp;
	private long flags;

	private DumpFileReader reader;
	private long index;

	MdmpFileHeader(DumpFileReader reader, long index) throws IOException {
		this.reader = reader;
		this.index = index;

		parse();
	}

	private void parse() throws IOException {
		reader.setPointerIndex(index);

		setSignature(reader.readNextInt());
		setVersion(reader.readNextInt());
		setNumberOfStreams(reader.readNextInt());
		setStreamDirectoryRVA(reader.readNextInt());
		setCheckSum(reader.readNextInt());
		setTimeDateStamp(reader.readNextInt());
		setFlags(reader.readNextLong());
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	public DataType toDataType() throws DuplicateNameException {
		StructureDataType struct = new StructureDataType(NAME, 0);

		struct.add(STRING, 4, "Signature", null);
		struct.add(STRING, 4, "Version", null);
		struct.add(DWORD, 4, "NumberOfStreams", null);
		struct.add(Pointer32DataType.dataType, 4, "StreamDirectoryRVA", null);
		struct.add(DWORD, 4, "CheckSum", null);

		UnionDataType union = new UnionDataType(NAME + "_u");
		union.add(DWORD, 4, "Reserved", null);
		union.add(DWORD, 4, "TimeDateStamp", null);
		struct.add(union, 4, union.getDisplayName(), null);

		struct.add(QWORD, 8, "Flags", null);

		struct.setCategoryPath(new CategoryPath("/MDMP"));

		return struct;
	}

	public void setSignature(int signature) {
		this.signature = signature;
	}

	public int getSignature() {
		return signature;
	}

	public void setVersion(int version) {
		this.version = version;
	}

	public int getVersion() {
		return version;
	}

	public void setNumberOfStreams(int numberOfStreams) {
		this.numberOfStreams = numberOfStreams;
	}

	public int getNumberOfStreams() {
		return numberOfStreams;
	}

	public void setStreamDirectoryRVA(long streamDirectoryRVA) {
		this.streamDirectoryRVA = streamDirectoryRVA;
	}

	public long getStreamDirectoryRVA() {
		return streamDirectoryRVA;
	}

	public void setCheckSum(int checkSum) {
		this.checkSum = checkSum;
	}

	public int getCheckSum() {
		return checkSum;
	}

	public void setTimeDateStamp(int timeDateStamp) {
		this.timeDateStamp = timeDateStamp;
	}

	public int getTimeDateStamp() {
		return timeDateStamp;
	}

	public void setFlags(long flags) {
		this.flags = flags;
	}

	public long getFlags() {
		return flags;
	}

}
