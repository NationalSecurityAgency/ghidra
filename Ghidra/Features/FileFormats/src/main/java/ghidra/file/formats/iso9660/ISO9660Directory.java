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
package ghidra.file.formats.iso9660;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.LocalDateTime;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class ISO9660Directory implements StructConverter {

	private int directoryRecordLength;
	private byte extendedAttributeRecordLen;
	private int locationOfExtentLE;
	private int locationOfExtentBE;
	private int dataLengthLE;
	private int dataLengthBE;
	private byte[] recordingDateTime;
	private byte fileFlag;
	private byte fileUnitSize;
	private byte interleaveGapSize;
	private short volumeSequenceNumberLE;
	private short volumeSequenceNumberBE;
	private byte fileIdentLength;
	private byte[] fileIdentifier;
	private byte paddingField;
	private boolean paddingFieldPresent;
	private long volumeIndex;
	private String name;
	private ISO9660Directory parentDir;

	public ISO9660Directory(BinaryReader reader) throws IOException {
		this(reader, null);
	}

	public ISO9660Directory(BinaryReader reader, ISO9660Directory parentDir) throws IOException {
		this.parentDir = parentDir;
		volumeIndex = reader.getPointerIndex();

		directoryRecordLength = reader.readNextByte() & 0xff;
		extendedAttributeRecordLen = reader.readNextByte();
		locationOfExtentLE = reader.readNextInt();
		locationOfExtentBE = readIntBigEndian(reader);
		dataLengthLE = reader.readNextInt();
		dataLengthBE = readIntBigEndian(reader);
		recordingDateTime = reader.readNextByteArray(ISO9660Constants.DATE_TIME_LENGTH_7);
		fileFlag = reader.readNextByte();
		fileUnitSize = reader.readNextByte();
		interleaveGapSize = reader.readNextByte();
		volumeSequenceNumberLE = reader.readNextShort();
		volumeSequenceNumberBE = readShortBigEndian(reader);
		fileIdentLength = reader.readNextByte();
		fileIdentifier = reader.readNextByteArray(fileIdentLength);
		name = analyzeName(fileIdentifier);

		//The padding field will only be present if the
		//fileIdentLength is even, otherwise it is not used
		if (fileIdentLength % 2 == 0) {
			paddingField = reader.readNextByte();
			paddingFieldPresent = true;
		}
		else {
			paddingFieldPresent = false;
		}
	}

	private int readIntBigEndian(BinaryReader reader) throws IOException {
		setReaderToBigEndian(reader);
		int tmp = reader.readNextInt();
		setReaderToLittleEndian(reader);

		return tmp;
	}

	private short readShortBigEndian(BinaryReader reader) throws IOException {
		setReaderToBigEndian(reader);
		short tmp = reader.readNextShort();
		setReaderToLittleEndian(reader);

		return tmp;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struc;
		struc = new StructureDataType("ISO9600Directory", 0);

		struc.add(BYTE, "Directory Record Length", "Length of the Directory Record");
		struc.add(BYTE, "Extended Attribute Record Length",
			"Length of the Extended Attribute Record");
		struc.add(QWORD, "Location of Extent", "LBA in (Little/Big)Endian (4 bytes each)");
		struc.add(QWORD, "Data Length", "Size of extent. (Little/Big)Endian (4 bytes each");
		struc.add(new ArrayDataType(BYTE, recordingDateTime.length, 1), "Recording date/time",
			"Recording date and time");
		struc.add(BYTE, "File flags", "File flags");
		struc.add(BYTE, "File Unit Size", "File unit size for files recoraded in interleaved mode");
		struc.add(BYTE, "Interleave gap size",
			"Interleave gap size for files recorded in interleaved mode");
		struc.add(DWORD, "Volume Sequence Number", "The clume that this extent is recorded in");
		struc.add(BYTE, "File Identifier Length", "Length of the file identifier");
		struc.add(new ArrayDataType(BYTE, fileIdentifier.length, 1), "File Identifier",
			"File Identifier");
		if (paddingFieldPresent) {
			struc.add(BYTE, "Padding Field", "Padding Field");
		}

		return struc;
	}

	/**
	 * Creates a string representation of this class filling in field specifics
	 * when applicable. 
	 * @return the string representation of this class
	 */
	@Override
	public String toString() {
		StringBuilder buff = new StringBuilder();

		buff.append("Directory Record Length: 0x" + Integer.toHexString(directoryRecordLength) +
			"\n");
		buff.append("Extended Attribute Record Length: 0x" +
			Integer.toHexString(extendedAttributeRecordLen) + "\n");
		buff.append("Extent Location: 0x" + Integer.toHexString(getLocationOfExtentLE()) + "\n");
		buff.append("Data Length: 0x" + Integer.toHexString(getDataLengthLE()) + "\n");
		buff.append("Recording Date/Time: " + createDateTimeString(recordingDateTime) + "\n");
		buff.append(getFileFlagString() + "\n");
		buff.append("File Unit Size Interleaved Mode: 0x" + Integer.toHexString(fileUnitSize) +
			"\n");
		buff.append("Interleave Gap Size: 0x" + Integer.toHexString(interleaveGapSize) + "\n");
		buff.append("Volume Sequence Number: 0x" +
			Integer.toHexString(getVolumeSequenceNumberLE()) + "\n");
		buff.append("Length of File Identifier: 0x" + Integer.toHexString(fileIdentLength) + "\n");
		buff.append("File Identifier: " + new String(fileIdentifier).trim() + "\n");
		if (paddingFieldPresent) {
			buff.append("Padding Field: 0x" + Integer.toHexString(paddingField) + "\n");
		}

		return buff.toString();
	}

	/*
	 * Looks at the fileIdentifier and checks if it is made up
	 * of visible not null ascii characters otherwise returns null
	 */
	private String analyzeName(byte[] bArr) {
		for (int i = 0; i < bArr.length; i++) {
			if (bArr[i] < 32) {
				return null;
			}
		}
		String tmp = new String(bArr);
		return tmp;
	}

	public boolean isDirectoryFlagSet() {
		if (getFlagBit(fileFlag, ISO9660Constants.DIRECTORY_FLAG) == 1) {
			return true;
		}
		return false;
	}

	ByteProvider getByteProvider(ByteProvider provider, long logicalBlockSize, FSRL fsrl) {

		if (!this.isDirectoryFlagSet()) {
			long index = locationOfExtentLE * logicalBlockSize;
			return new ByteProviderWrapper(provider, index, dataLengthLE, fsrl);
		}
		return null;
	}

	/*
	 * Parses the flag byte to return the string representation
	 * of the flags bits which are set
	 */
	private String getFileFlagString() {
		String flagString = "";
		flagString += "File Flags:\n";
		if (getFlagBit(fileFlag, ISO9660Constants.HIDDEN_FILE_FLAG) == 1) {
			flagString += "\tHidden File Flag Set";
		}
		if (getFlagBit(fileFlag, ISO9660Constants.DIRECTORY_FLAG) == 1) {
			flagString += "\tDirectory Flag Set";
		}
		if (getFlagBit(fileFlag, ISO9660Constants.ASSOCIATED_FILE_FLAG) == 1) {
			flagString += "\tAssociated File Flag Set";
		}
		if (getFlagBit(fileFlag, ISO9660Constants.EXTENDED_ATTRIBUTE_RECORD_INFO_FLAG) == 1) {
			flagString += "\tExtended Attribute Record Info Flag Set";
		}
		if (getFlagBit(fileFlag, ISO9660Constants.NOT_FINAL_DIRECTORY_RECORD_FLAG) == 1) {
			flagString += "\tNot Final Directory Record Flag";
		}

		return flagString;
	}

	private byte getFlagBit(byte flagByte, int flagIndex) {
		return (byte) ((flagByte >>> flagIndex) & 1);
	}

	/**
	 * Parses the given buffer as an ISO9660 timestamp and returns it as a
	 * human readable string representation.
	 *
	 * Invalid buffers that are still big enough to hold a timestamp are
	 * still parsed and converted, albeit they are marked as invalid when
	 * presented to the user.
	 *
	 * @param byteArray the buffer to parse (both standard and extended
	 *                     formats are handled).
	 * @return a string with the human readable timestamp.
	 */
	private String createDateTimeString(byte[] byteArray) {
		if (byteArray == null || byteArray.length < 7) {
			return "INVALID (truncated or missing)";
		}

		// Time zone offset from GMT in 15 minute intervals,
		// starting at interval -48 (west) and running up to
		// interval 52 (east)
		int timeOffset = byteArray[byteArray.length - 1];

		int i1, i2, i3, i4, i5, i6;
		i1 = 1900 + byteArray[0]; // Years since 1900
		i2 = byteArray[1];        // Month of year
		i3 = byteArray[2];        // Day of month
		i4 = byteArray[3];        // Hour of day
		i5 = byteArray[4];        // Minute of hour
		i6 = byteArray[5];        // Second of minute

		// The buffer contains an invalid timezone offset.
		boolean validBuffer = true;
		if (timeOffset < -48 || timeOffset > 52) {
			validBuffer = false;
		}

		// The buffer contains an invalid date/time.
		try {
			LocalDateTime.of(i1, i2, i3, i4, i5, i6);
		} catch (DateTimeException exception) {
			validBuffer = false;
		}

		StringBuilder builder = new StringBuilder();
		if (!validBuffer) {
			builder.append("INVALID (");
		}
		int timezoneIntegral = timeOffset / 4;
		int timezoneFractional = (Math.abs(timeOffset) % 4) * 15;
		builder.append(String.format("%04d-%02d-%02d %02d:%02d:%02d GMT%c%02d%02d", i1, i2, i3,
				i4, i5, i6, timezoneIntegral < 0 ? '-' : '+', timezoneIntegral, timezoneFractional));
		if (!validBuffer) {
			builder.append(")");
		}

		return builder.toString();
	}

	private void setReaderToBigEndian(BinaryReader reader) {
		reader.setLittleEndian(false);
	}

	private void setReaderToLittleEndian(BinaryReader reader) {
		reader.setLittleEndian(true);
	}

	public long getVolumeIndex() {
		return volumeIndex;
	}

	public int getDirectoryRecordLength() {
		return directoryRecordLength;
	}

	public byte getExtendedAttributeRecordLen() {
		return extendedAttributeRecordLen;
	}

	public byte[] getRecordingDateTime() {
		return recordingDateTime;
	}

	public byte getFileFlag() {
		return fileFlag;
	}

	public byte getFileUnitSize() {
		return fileUnitSize;
	}

	public byte getInterleaveGapSize() {
		return interleaveGapSize;
	}

	public int getLocationOfExtentLE() {
		return locationOfExtentLE;
	}

	public int getLocationOfExtentBE() {
		return locationOfExtentBE;
	}

	public int getDataLengthLE() {
		return dataLengthLE;
	}

	public int getDataLengthBE() {
		return dataLengthBE;
	}

	public short getVolumeSequenceNumberLE() {
		return volumeSequenceNumberLE;
	}

	public short getVolumeSequenceNumberBE() {
		return volumeSequenceNumberBE;
	}

	public byte getFileIdentLength() {
		return fileIdentLength;
	}

	public byte[] getFileIdentifier() {
		return fileIdentifier;
	}

	public byte getPaddingField() {
		return paddingField;
	}

	public boolean isPaddingFieldPresent() {
		return paddingFieldPresent;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public ISO9660Directory getParentDirectory() {
		return parentDir;
	}

	public void setParentDirectory(ISO9660Directory parentDir) {
		this.parentDir = parentDir;
	}

}
