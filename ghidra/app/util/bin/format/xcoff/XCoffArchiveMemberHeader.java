/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.bin.format.xcoff;

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

/**
 * The <code>ARHeader</code> class is used to store the per-object file 
 *  archive headers.  It can also create an XCOFF32 object for inspecting
 *  the object file data.
 */
public class XCoffArchiveMemberHeader {
	private static final int _02 =  2;
	private static final int _04 =  4;
	private static final int _12 = 12;
	private static final int _20 = 20;

	private byte [] ar_size;    // File member size - decimal
	private byte [] ar_nxtmem;  // Next member offset - decimal
	private byte [] ar_prvmem;  // Previous member offset - decimal
	private byte [] ar_date;    // File member date - decimal
	private byte [] ar_uid;     // File member userid - decimal
	private byte [] ar_gid;     // File member group id - decimal
	private byte [] ar_mode;    // File member mode - octal
	private byte [] ar_namlen;  // File member name length -decimal
	private byte [] ar_name;    // Start of member name
	private byte [] ar_fmag;    // AIAFMAG - string to end "`\n"

	long file_offset;

	public XCoffArchiveMemberHeader(BinaryReader reader) throws IOException {
		ar_size   = reader.readNextByteArray(_20);
		ar_nxtmem = reader.readNextByteArray(_20);
		ar_prvmem = reader.readNextByteArray(_20);
		ar_date   = reader.readNextByteArray(_12);
		ar_uid    = reader.readNextByteArray(_12);
		ar_gid    = reader.readNextByteArray(_12);
		ar_mode   = reader.readNextByteArray(_12);
		ar_namlen = reader.readNextByteArray(_04);
		ar_name   = reader.readNextByteArray(getNameLength());
		ar_fmag   = reader.readNextByteArray(_02);
		//
		// Save this location so we can create the XCOFF object later.
		//
		file_offset = reader.getPointerIndex();
		if ((file_offset % 2) == 1) {
			++file_offset;
		}
	}

	public long getSize() {
		return Long.parseLong((new String(ar_size)).trim());
	}
	public long getNextMemberOffset() {
		return Long.parseLong((new String(ar_nxtmem)).trim());
	}
	public long getPreviousMemberOffset() {
		return Long.parseLong((new String(ar_prvmem)).trim());
	}
	public long getDate() {
		return Long.parseLong((new String(ar_date)).trim());
	}
	public long getUserID() {
		return Long.parseLong((new String(ar_uid)).trim());
	}
	public long getGroupID() {
		return Long.parseLong((new String(ar_gid)).trim());
	}
	public long getMode() {
		return Long.parseLong((new String(ar_mode)).trim());
	}
	public int getNameLength() {
		return Integer.parseInt((new String(ar_namlen)).trim());
	}
	public String getName() {
		return (new String(ar_name)).trim();
	}
	public String getTerminator() {
		return (new String(ar_fmag)).trim();
	}

	public long getObjectDataOffset() {
		return file_offset;
	}

}
