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

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.LocalDateTime;

public class ISO9660VolumeDescriptor extends ISO9660BaseVolume {
	private byte unused;                        // Always 0x00
	private byte[] systemIdentifier;            // Length 0x20
	private byte[] volumeIdentifier;            // Length 0x20
	private long unused2;                        // All 0x00
	private int volumeSpaceSizeLE;                // Little-endian
	private int volumeSpaceSizeBE;                // Big-endian
	private byte[] unused3;                        //  Length 0x20
	private short volumeSetSizeLE;                // Little-endian
	private short volumeSetSizeBE;                // Big-endian
	private short volumeSeqNumberLE;            // Little-endian
	private short volumeSeqNumberBE;            // Big-endian
	private short logicalBlockSizeLE;            // Little-endian
	private short logicalBlockSizeBE;            // Big-endian
	private int pathTableSizeLE;                // Litte-endian
	private int pathTableSizeBE;                // Big-endian
	private int typeLPathTableLocation;         // -int32_LSB-
	private int optionalTypeLPathTableLocation; // -int32_LSB-
	private int typeMPathTableLocation;            // -int32_MSB-
	private int optionalTypeMPathTableLocation;    // -int32_MSB-
	private ISO9660Directory directoryEntry;     // Length 0x20
	private byte[] volumeSetIdentifier;            // Length 0x80
	private byte[] publisherIdentifier;            // Length 0x80
	private byte[] dataPreparerIdentifier;        // Length 0x80
	private byte[] applicationIdentifier;        // Length 0x80
	private byte[] copyrightFileIdentifier;        // Length 0x26
	private byte[] abstractFileIdentifier;         // Length 0x24
	private byte[] bibliographicFileIdentifier; // Length 0x25
	private byte[] volumeCreationDateTime;        // Length 0x11
	private byte[] volumeModifyDateTime;        // Length 0x11
	private byte[] volumeExpirationDateTime;    // Length 0x11
	private byte[] volumeEffectiveDateTime;        // length 0x11 
	private byte fileStructureVersion;            // -int8-
	private byte unused4;                        // Always 0x00
	private byte[] applicationUsed;                // Length 0x200
	private byte[] reserved;                    // Length 0x28D

	public ISO9660VolumeDescriptor(BinaryReader reader) throws IOException {

		super(reader);
		unused = reader.readNextByte();
		systemIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_32);
		volumeIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_32);
		unused2 = reader.readNextLong();
		volumeSpaceSizeLE = reader.readNextInt();
		volumeSpaceSizeBE = readIntBigEndian(reader);
		unused3 = reader.readNextByteArray(ISO9660Constants.UNUSED_SPACER_LEN_32);
		volumeSetSizeLE = reader.readNextShort();
		volumeSetSizeBE = readShortBigEndian(reader);
		volumeSeqNumberLE = reader.readNextShort();
		volumeSeqNumberBE = readShortBigEndian(reader);
		logicalBlockSizeLE = reader.readNextShort();
		logicalBlockSizeBE = readShortBigEndian(reader);
		pathTableSizeLE = reader.readNextInt();
		pathTableSizeBE = readIntBigEndian(reader);
		typeLPathTableLocation = reader.readNextInt();
		optionalTypeLPathTableLocation = reader.readNextInt();
		typeMPathTableLocation = readIntBigEndian(reader);
		optionalTypeMPathTableLocation = readIntBigEndian(reader);
		directoryEntry = new ISO9660Directory(reader);
		volumeSetIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_128);
		publisherIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_128);
		dataPreparerIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_128);
		applicationIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_128);
		copyrightFileIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_38);
		abstractFileIdentifier = reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_36);
		bibliographicFileIdentifier =
			reader.readNextByteArray(ISO9660Constants.IDENTIFIER_LENGTH_37);
		volumeCreationDateTime = reader.readNextByteArray(ISO9660Constants.DATE_TIME_LENGTH_17);
		volumeModifyDateTime = reader.readNextByteArray(ISO9660Constants.DATE_TIME_LENGTH_17);
		volumeExpirationDateTime = reader.readNextByteArray(ISO9660Constants.DATE_TIME_LENGTH_17);
		volumeEffectiveDateTime = reader.readNextByteArray(ISO9660Constants.DATE_TIME_LENGTH_17);
		fileStructureVersion = reader.readNextByte();
		unused4 = reader.readNextByte();
		applicationUsed = reader.readNextByteArray(ISO9660Constants.UNUSED_SPACER_LEN_512);
		reserved = reader.readNextByteArray(ISO9660Constants.RESERVED_SIZE);

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
		if (super.getTypeCode() == ISO9660Constants.VOLUME_DESC_PRIMARY_VOLUME_DESC) {
			struc = new StructureDataType("ISO9600PrimaryVolumeDescriptor", 0);
		}
		else if (super.getTypeCode() == ISO9660Constants.VOLUME_DESC_SUPPL_VOLUME_DESC) {
			struc = new StructureDataType("ISO9600SupplementaryVolumeDescriptor", 0);
		}
		else {
			struc = null;
		}

		struc.add(BYTE, "Type Code", "Type of volume descriptor");
		struc.add(new ArrayDataType(BYTE, super.getIdentifier().length, 1), "Standard Identifier",
			"Always 'CD001'");
		struc.add(BYTE, "Version", "Always 0x01");
		struc.add(BYTE, "Unused", "Always 0x00");
		struc.add(new ArrayDataType(BYTE, systemIdentifier.length, 1), "System Identifier",
			"Name of the system to act upon sectors 0x00-0x0F");
		struc.add(new ArrayDataType(BYTE, volumeIdentifier.length, 1), "Volume Identifier",
			"Identification for this volume");
		struc.add(QWORD, "Unused", "Always 0x00");
		struc.add(QWORD, "Volume Space Size", "Number of logical blocks the volume is recorded");
		struc.add(new ArrayDataType(BYTE, unused3.length, 1), "Unused", "Always 0x00");
		struc.add(DWORD, "Volume Set Size", "Size of the set in this logical volume");
		struc.add(DWORD, "Volume Sequence Number", "Number of disks in volume set");
		struc.add(DWORD, "Logical block Size", "Size of the logical block");
		struc.add(QWORD, "Path Table Size", "Size of the path table");
		struc.add(DWORD, "Location of Type-L Path Dable",
			"LBA location of the path table containing only litle-endian values");
		struc.add(DWORD, "Location of Optional Type-L Path Table",
			"LBA location of the optional path table containing only little-endian values");
		struc.add(DWORD, "Location of Type-M Path Table",
			"LBA location of the path table containing only big-endian values");
		struc.add(DWORD, "Location of Optional Type-M Path Table",
			"LBA location of the optional path table containing only big-endian values");
		struc.add(directoryEntry.toDataType());
		struc.add(new ArrayDataType(BYTE, volumeSetIdentifier.length, 1), "Volume Set Identifier",
			"Identifier of the volume set which this volume is a member");
		struc.add(new ArrayDataType(BYTE, publisherIdentifier.length, 1), "Publisher Identifier",
			"The volume publisher");
		struc.add(new ArrayDataType(BYTE, dataPreparerIdentifier.length, 1),
			"Data Preparer Identifier", "Identifier of person(s) who prepared data for this volume");
		struc.add(new ArrayDataType(BYTE, applicationIdentifier.length, 1),
			"Application Identifier", "How the data are recorded on this volume");
		struc.add(new ArrayDataType(BYTE, copyrightFileIdentifier.length, 1),
			"Copyright File Identifier",
			"Filename of file that contains copyright information on volume set");
		struc.add(new ArrayDataType(BYTE, abstractFileIdentifier.length, 1),
			"Abstract File Identifier",
			"Filename of file that contains abstract information on volume set");
		struc.add(new ArrayDataType(BYTE, bibliographicFileIdentifier.length, 1),
			"Bibliographic File Identifier",
			"Filename of file that contians bibliographic information on volume set");
		struc.add(new ArrayDataType(BYTE, volumeCreationDateTime.length, 1),
			"Volume Creation Date and Time", "Date and time volume was created");
		struc.add(new ArrayDataType(BYTE, volumeModifyDateTime.length, 1),
			"Volume Modification Date and Time", "Date and time volume was modified");
		struc.add(new ArrayDataType(BYTE, volumeExpirationDateTime.length, 1),
			"Volume Expiration Date and Time", "Date and time volume was created");
		struc.add(new ArrayDataType(BYTE, volumeEffectiveDateTime.length, 1),
			"Volume Effective Date and Time", "Date and time after which the volume may be used");
		struc.add(BYTE, "File Structure Version", "Directory records and path table version");
		struc.add(BYTE, "Unused", "Always 0x00");
		struc.add(new ArrayDataType(BYTE, applicationUsed.length, 1), "Application Used",
			"Contents not defined by ISO 9660");
		struc.add(new ArrayDataType(BYTE, reserved.length, 1), "Reserved", "Reserved by ISO");

		return struc;
	}

	@Override
	public String toString() {
		StringBuilder buff = new StringBuilder();

		buff.append("Type Code: 0x" + Integer.toHexString(super.getTypeCode()) + " => " +
			getTypeCodeString() + "\n");
		buff.append("Standard Identifier: " + new String(super.getIdentifier()).trim() + "\n");
		buff.append("Version: 0x" + Integer.toHexString(super.getVersion()) + "\n");
		buff.append("Unused: 0x" + Integer.toHexString(unused) + "\n");
		buff.append("System Identifier: " + new String(systemIdentifier).trim() + "\n");
		buff.append("Volume Identifier: " + new String(volumeIdentifier).trim() + "\n");
		buff.append("Unused Field: 0x" + Long.toHexString(unused2) + "\n");
		buff.append("Volume Space Size: 0x" + Integer.toHexString(getVolumeSpaceSizeLE()) + "\n");
		buff.append("Unused: " + new String(unused3).trim() + "\n");
		buff.append("Volume Set Size: 0x" + Integer.toHexString(getVolumeSetSizeLE()) + "\n");
		buff.append("Volume Sequence Number: 0x" + Integer.toHexString(getVolumeSeqNumberLE()) +
			"\n");
		buff.append("Logical Block Size: 0x" + Integer.toHexString(getLogicalBlockSizeLE()) + "\n");
		buff.append("Path Table Size: 0x" + Integer.toHexString(getPathTableSizeLE()) + "\n");
		buff.append("LBA Location of Type-L Path Table: 0x" +
			Integer.toHexString(typeLPathTableLocation) + "\n");
		buff.append("LBA Location of Optional Type-L Path Table: 0x" +
			Integer.toHexString(optionalTypeLPathTableLocation) + "\n");
		buff.append("LBA Location of Type-M Path Table: 0x" +
			Integer.toHexString(typeMPathTableLocation) + "\n");
		buff.append("LBA Location of Optional Type-M Path Table: 0x" +
			Integer.toHexString(optionalTypeMPathTableLocation) + "\n");
		buff.append("Calculated Location of Type-L Path Table: 0x" +
			Integer.toHexString(typeLPathTableLocation * getLogicalBlockSizeLE()) + "\n");
		buff.append("Calculated Location of Type-M Path Table: 0x" +
			Integer.toHexString(typeMPathTableLocation * getLogicalBlockSizeBE()) + "\n");
		buff.append("Directory Entry for Root Directory: \n" + directoryEntry.toString() + "\n");
		buff.append("Volume Set Identifier: " + new String(volumeSetIdentifier).trim() + "\n");
		buff.append("Publisher Identifier: " + new String(publisherIdentifier).trim() + "\n");
		buff.append("Data Preparer Identifier: " + new String(dataPreparerIdentifier).trim() + "\n");
		buff.append("Application Identifier: " + new String(applicationIdentifier).trim() + "\n");
		buff.append("Copyright File Identifier: " + new String(copyrightFileIdentifier).trim() +
			"\n");
		buff.append("Abstract File Identifier: " + new String(abstractFileIdentifier).trim() + "\n");
		buff.append("Biliographic File Identifier: " + new String(bibliographicFileIdentifier) +
			"\n");
		buff.append("Volume Creation Date/Time: " + createDateTimeString(volumeCreationDateTime) +
			"\n");
		buff.append("Volume Modification Date/Time: " + createDateTimeString(volumeModifyDateTime) +
			"\n");
		buff.append("Volume Expiration Date/Time: " + createDateTimeString(volumeCreationDateTime) +
			"\n");
		buff.append("Volume Effective Date/Time: " + createDateTimeString(volumeEffectiveDateTime) +
			"\n");
		buff.append("File Structure Version: 0x" + Integer.toHexString(fileStructureVersion) + "\n");
		buff.append("Unused: 0x" + Integer.toHexString(unused4) + "\n");

		return buff.toString();
	}

	/**
	 * Checks whether the given string is entirely made up of ASCII digits.
	 *
	 * @param string the string to check.
	 * @return true if all characters in the string are ASCII digits, false
	 * otherwise.
	 */
	private boolean isDigitsStringValid(String string) {
		for (int i = 0; i < string.length(); i++) {
			char c = string.charAt(i);
			if (c < '0' || c > '9') {
				return false;
			}
		}

		return true;
	}

	/**
	 * Parses the given buffer as an ISO9660 timestamp and returns it as a
	 * human readable string representation.
	 *
	 * Invalid buffers that are still big enough to hold a timestamp are
	 * still parsed and converted, albeit they are marked as invalid when
	 * presented to the user.
	 *
	 * @param byteArray the buffer to parse (only extended timestamp format
	 *                  is handled).
	 * @return a string with the human readable timestamp.
	 */
	protected String createDateTimeString(byte[] byteArray) {
		if (byteArray == null || byteArray.length < 17) {
			return "INVALID (truncated or missing)";
		}

		String s1, s2, s3, s4, s5, s6, s7;

		// Time zone offset from GMT in 15 minute intervals,
		// starting at interval -48 (west) and running up to
		// interval 52 (east)
		int timeOffset = byteArray[byteArray.length - 1];

		String bString = new String(byteArray);
		s1 = bString.substring(0, 4);   //year 1 to 9999
		s2 = bString.substring(4, 6);   //month 1 to 12
		s3 = bString.substring(6, 8);   //day 1 to 31
		s4 = bString.substring(8, 10);  //hour 0 to 23
		s5 = bString.substring(10, 12); //minute 0 to 59
		s6 = bString.substring(12, 14); //second 0 to 59
		s7 = bString.substring(14, 16); //ms 0 to 99

		// Validate strings first.
		boolean validBuffer = isDigitsStringValid(s1) && isDigitsStringValid(s2) && isDigitsStringValid(s3) &&
				isDigitsStringValid(s4) && isDigitsStringValid(s5) && isDigitsStringValid(s6) && isDigitsStringValid(s7);

		try {
			// The buffer contains an invalid date/time.
			LocalDateTime.of(Integer.parseInt(s1), Integer.parseInt(s2), Integer.parseInt(s3),
					Integer.parseInt(s4), Integer.parseInt(s5), Integer.parseInt(s6));
		} catch (NumberFormatException | DateTimeException e) {
			validBuffer = false;
		}

		// The buffer contains an invalid timezone offset.
		if (timeOffset < -48 || timeOffset > 52) {
			validBuffer = false;
		}

		/*
		 * Time zone offset from GMT in 15 minute intervals,
		 * starting at interval -48 (west) and running up to
		 * interval 52 (east).
		 */
		int timezoneIntegral = timeOffset / 4;
		int timezoneFractional = (Math.abs(timeOffset) % 4) * 15;

		StringBuilder builder = new StringBuilder();
		if (!validBuffer) {
			builder.append("INVALID(");
		}

		builder.append(String.format("%s-%s-%s %s:%s:%s.%s GMT%c%02d%02d", s1, s2, s3, s4, s5, s6, s7,
			timezoneIntegral < 0 ? '-' : '+', timezoneIntegral, timezoneFractional));

		if (!validBuffer) {
			builder.append(")");
		}

		return builder.toString();
	}

	public byte getUnused() {
		return unused;
	}

	public byte[] getSystemIdentifier() {
		return systemIdentifier;
	}

	public byte[] getVolumeIdentifier() {
		return volumeIdentifier;
	}

	public long getUnused2() {
		return unused2;
	}

	public byte[] getUnused3() {
		return unused3;
	}

	public int getVolumeSpaceSizeLE() {
		return volumeSpaceSizeLE;
	}

	public int getVolumeSpaceSizeBE() {
		return volumeSpaceSizeBE;
	}

	public short getVolumeSetSizeLE() {
		return volumeSetSizeLE;
	}

	public short getVolumeSetSizeBE() {
		return volumeSetSizeBE;
	}

	public short getVolumeSeqNumberLE() {
		return volumeSeqNumberLE;
	}

	public short getVolumeSeqNumberBE() {
		return volumeSeqNumberBE;
	}

	public short getLogicalBlockSizeLE() {
		return logicalBlockSizeLE;
	}

	public short getLogicalBlockSizeBE() {
		return logicalBlockSizeBE;
	}

	public int getPathTableSizeLE() {
		return pathTableSizeLE;
	}

	public int getPathTableSizeBE() {
		return pathTableSizeBE;
	}

	public int getTypeLPathTableLocation() {
		return typeLPathTableLocation;
	}

	public int getOptionalTypeLPathTableLocation() {
		return optionalTypeLPathTableLocation;
	}

	public int getTypeMPathTableLocation() {
		return typeMPathTableLocation;
	}

	public int getOptionalTypeMPathTableLocation() {
		return optionalTypeMPathTableLocation;
	}

	public ISO9660Directory getDirectoryEntry() {
		return directoryEntry;
	}

	public byte[] getVolumeSetIdentifier() {
		return volumeSetIdentifier;
	}

	public byte[] getPublisherIdentifier() {
		return publisherIdentifier;
	}

	public byte[] getDataPreparerIdentifier() {
		return dataPreparerIdentifier;
	}

	public byte[] getApplicationIdentifier() {
		return applicationIdentifier;
	}

	public byte[] getCopyrightFileIdentifier() {
		return copyrightFileIdentifier;
	}

	public byte[] getAbstractFileIdentifier() {
		return abstractFileIdentifier;
	}

	public byte[] getBibliographicFileIdentifier() {
		return bibliographicFileIdentifier;
	}

	public byte[] getVolumeCreationDateTime() {
		return volumeCreationDateTime;
	}

	public byte[] getVolumeModifyDateTime() {
		return volumeModifyDateTime;
	}

	public byte[] getVolumeExpirationDateTime() {
		return volumeExpirationDateTime;
	}

	public byte[] getVolumeEffectiveDateTime() {
		return volumeEffectiveDateTime;
	}

	public byte getFileStructureVersion() {
		return fileStructureVersion;
	}

	public byte getUnused4() {
		return unused4;
	}

	public byte[] getApplicationUsed() {
		return applicationUsed;
	}

	public byte[] getReserved() {
		return reserved;
	}

	private void setReaderToBigEndian(BinaryReader reader) {
		reader.setLittleEndian(false);
	}

	private void setReaderToLittleEndian(BinaryReader reader) {
		reader.setLittleEndian(true);
	}

}
