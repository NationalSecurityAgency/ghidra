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
package ghidra.app.util.bin.format.coff.archive;

import ghidra.app.util.bin.*;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class CoffArchiveMemberHeader implements StructConverter {
	public static final String SLASH = "/";
	public static final String SLASH_SLASH = "//";

	private static final int CAMH_NAME_OFF = 0;
	private static final int CAMH_NAME_LEN = 16;

	private static final int CAMH_DATE_OFF = 16;
	private static final int CAMH_DATE_LEN = 12;

	private static final int CAMH_USERID_OFF = 28;
	private static final int CAMH_USERID_LEN = 6;

	private static final int CAMH_GROUPID_OFF = 34;
	private static final int CAMH_GROUPID_LEN = 6;

	private static final int CAMH_MODE_OFF = 40;
	private static final int CAMH_MODE_LEN = 8;

	private static final int CAMH_SIZE_OFF = 48;
	private static final int CAMH_SIZE_LEN = 10;

	private static final int CAMH_EOH_OFF = 58;
	private static final int CAMH_EOH_LEN = 2;
	private static final String CAMH_EOH_MAGIC = "`\n";

	private static final int CAMH_PAYLOAD_OFF = 60;
	public static final int CAMH_MIN_SIZE = CAMH_PAYLOAD_OFF;

	/**
	 * Reads a COFF archive member header from the specified {@link BinaryReader reader},
	 * leaving the file position at the start of the this member's payload.
	 * <p>
	 * The archive member's name is fixed up using the specified {@link LongNamesMember longNames}
	 * object.
	 * <p>
	 * @param reader stream from which to read the COFF archive member header from
	 * @param longNames optional, string table with long file names (only present in some 
	 * COFF ar formats)
	 * @return a new {@link CoffArchiveMemberHeader}
	 * @throws IOException
	 */
	public static CoffArchiveMemberHeader read(BinaryReader reader, LongNamesMember longNames)
			throws IOException {
		align(reader);

		long headerOffset = reader.getPointerIndex();

		/*
		 * Decoding the name field:
		 * 
		 * "/nnn" - a slash followed by a ascii integer string indicates that the actual name
		 * is located at offset "nnn" in the "longnames" string table.
		 * 
		 * "#1/nnn" - a "#1/", followed by an ascii integer string indicates that the
		 * actual name is located at the beginning of the payload of this member, and its
		 * length is 'nnn' bytes.  The actual payload starts after the end of the name and
		 * its effective size needs to be reduced by the filename length. 
		 * 
		 * "name/"
		 * The field gives the name of the archive member directly.
		 * 
		 * "/"
		 * The archive member is one of the two linker members.
		 * Both of the linker members have this name.
		 * 
		 * "//"
		 * The archive member is the longname member, which
		 * consists of a series of terminated ASCII strings.
		 * The longnames member is the third archive member
		 */
		String name =
			reader.readFixedLenAsciiString(headerOffset + CAMH_NAME_OFF, CAMH_NAME_LEN).trim();
		
		/*
		 * The number of seconds since 1/1/1970 UCT 
		 */
		String dateStr =
			reader.readFixedLenAsciiString(headerOffset + CAMH_DATE_OFF, CAMH_DATE_LEN).trim();
		
		/*
		 * Ascii integer string or blank
		 */
		String userId =
			reader.readFixedLenAsciiString(headerOffset + CAMH_USERID_OFF, CAMH_USERID_LEN).trim();
		
		/*
		 * Ascii integer string or blank
		 */
		String groupId = reader.readFixedLenAsciiString(headerOffset + CAMH_GROUPID_OFF,
			CAMH_GROUPID_LEN).trim();
		
		/*
		 * Ascii integer string of ST_MODE value from the C run-time function _wstat
		 */
		String mode =
			reader.readFixedLenAsciiString(headerOffset + CAMH_MODE_OFF, CAMH_MODE_LEN).trim();
		
		/*
		 * Ascii integer string representing the total size of the archive member,
		 * not including the header.  If the name is stored at the beginning of the
		 * payload (ie. name == "#1/nnn"), the member's effective size needs to be adjusted.
		 */
		String sizeStr =
			reader.readFixedLenAsciiString(headerOffset + CAMH_SIZE_OFF, CAMH_SIZE_LEN).trim();
		
		/*
		 * Two byte Ascii string 0x60 0x0a ("'\n")
		 */
		String endOfHeader = reader.readFixedLenAsciiString(headerOffset + CAMH_EOH_OFF, CAMH_EOH_LEN);
		
		if (!endOfHeader.equals(CAMH_EOH_MAGIC)) {
			throw new IOException("Bad EOH magic string: " + endOfHeader);
		}

		long payloadOffset = headerOffset + CAMH_PAYLOAD_OFF;
		
		long size;
		try {
			size = Long.parseLong(sizeStr);
		} catch ( NumberFormatException nfe ) {
			throw new IOException("Bad size value: " + sizeStr);
		}
		
		if (name.startsWith("#1/")) {
			try {
				int nameLen = Integer.parseInt(name.substring(3));
				// name seems to be padded with trailing nulls to put payload at aligned offset
				name = StringUtilities.trimTrailingNulls(
					reader.readFixedLenAsciiString(payloadOffset, nameLen));
				size -= nameLen;
				payloadOffset += nameLen;
			} catch ( NumberFormatException nfe ) {
				throw new IOException("Bad name len value: " + name);
			}
		}
		else if (name.matches("/[0-9]+") && longNames != null) {
			try {
				long offset = Long.parseLong(name.substring(1));
				name = longNames.getStringAtOffset(reader.getByteProvider(), offset);
				if (name.endsWith("/")) {
					name = name.substring(0, name.length() - 1);
				}
			}
			catch (NumberFormatException nfe) {
				throw new IOException("Bad long name offset: " + name);
			}
		}
		else if (name.startsWith("/")) {
			// don't do any tweaking of the name, keeps "/" and "//" intact.
		}
		else if (name.endsWith("/")) {
			name = name.substring(0, name.length() - 1);
		}

		long date = 0;
		try {
			if (!dateStr.isEmpty()) {
				date = Long.parseLong(dateStr) * 1000 /* convert from seconds to millis */;
			}
		}
		catch (NumberFormatException nfe) {
			Msg.warn(null, "COFF Archive: bad date value: [" + dateStr + "] in " +
					reader.getByteProvider().getName() + " for [" + name + "] at file offset 0x" +
					Long.toHexString(headerOffset));
		}

		reader.setPointerIndex(payloadOffset);

		return new CoffArchiveMemberHeader(name, date, userId, groupId, mode, size, payloadOffset,
			headerOffset);
	}

	/**
	 * An archive member header should only start
	 * on even byte boundaries. This method
	 * will align the binary reader if needed.
	 * @param reader the binary reader to align
	 */
	private static void align(BinaryReader reader) {
		if ((reader.getPointerIndex()) % 2 != 0) {
			reader.setPointerIndex(reader.getPointerIndex() + 1);
		}
	}

	private String name;
	private long date;
	private String userId;
	private String groupId;
	private String mode;
	private long size;
	private long payloadOffset = -1;
	private long memberOffset = -1;

	public CoffArchiveMemberHeader(String name, long date, String userId, String groupId,
			String mode, long size, long payloadOffset, long memberOffset) {
		this.name = name;
		this.date = date;
		this.userId = userId;
		this.groupId = groupId;
		this.mode = mode;
		this.size = size;
		this.payloadOffset = payloadOffset;
		this.memberOffset = memberOffset;
	}

	public String getName() {
		return name;
	}

	/**
	 * Milliseconds since java Date epoch
	 * @return
	 */
	public long getDate() {
		return date;
	}

	public String getUserId() {
		return userId;
	}

	public String getGroupId() {
		return groupId;
	}

	public String getMode() {
		return mode;
	}

	public long getSize() {
		return size;
	}

	public long getPayloadOffset() {
		return payloadOffset;
	}

	public long getFileOffset() {
		return memberOffset;
	}

	/**
	 * Returns true if this header contains a COFF file.
	 * @return true if this header contains a COFF file
	 */
	public boolean isCOFF() {
		return !name.equals(CoffArchiveMemberHeader.SLASH) &&
			!name.equals(CoffArchiveMemberHeader.SLASH_SLASH);
	}

	public DataType toDataType() throws DuplicateNameException, IOException {
		String camh_name = StructConverterUtil.parseName(CoffArchiveMemberHeader.class);
		Structure struct = new StructureDataType(camh_name, 0);
		struct.add(STRING, CAMH_NAME_LEN, "name", null);
		struct.add(STRING, CAMH_DATE_LEN, "date", null);
		struct.add(STRING, CAMH_USERID_LEN, "userID", null);
		struct.add(STRING, CAMH_GROUPID_LEN, "groupID", null);
		struct.add(STRING, CAMH_MODE_LEN, "mode", null);
		struct.add(STRING, CAMH_SIZE_LEN, "size", null);
		struct.add(STRING, CAMH_EOH_LEN, "endOfHeader", null);
		return struct;
	}
}
