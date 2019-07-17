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
package ghidra.app.util.bin.format.omf;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.ArrayList;

public class OmfLibraryRecord extends OmfRecord {
	private int pageSize;		// All archive members must start on a page boundary of this size
	private long dictionaryOffset;
	private int dictionarySize;
	private byte flags;
	private ArrayList<MemberHeader> members;

	public static class MemberHeader {
		public long payloadOffset;		// Byte offset of the object within the library file
		public long size;				// Size of the object in bytes
		public String name;
		public String translator;
		public String machineName;
	}
	
	public OmfLibraryRecord(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		pageSize = recordLength + 3;
		dictionaryOffset = reader.readNextInt() & 0xffffffff;
		dictionarySize = reader.readNextShort() & 0xffff;
		flags = reader.readNextByte();
		// No checksum byte  (just padding)
	}
	
	public int getPageSize() {
		return pageSize;
	}
	
	public ArrayList<MemberHeader> getMemberHeaders() {
		return members;
	}
	
	public static boolean checkMagicNumer(BinaryReader reader) throws IOException {
		byte type = reader.readNextByte();
		if (type != (byte)0xF0)
			return false;

		int pageSize = (reader.readNextShort() & 0xffff) + 3;
		// Make sure page size is a power of 2,   2^4 - 2^15
		int count = 0;
		int mask = pageSize;
		while((mask & 1)==0) {
			count += 1;
			mask >>>= 1;
		}
		if (mask != 1) return false;		// Test if this is a power of 2
		if (count < 4) return false;
		if (count > 15) return false;
		reader.align(pageSize);
		type = reader.readNextByte();
		if ((type & 0xfc) != 0x80) return false;
		return true;
	}
	
	public static OmfLibraryRecord parse(BinaryReader reader,TaskMonitor monitor) throws IOException {
		OmfLibraryRecord res = null;
		byte type = reader.peekNextByte();
		if (type != (byte)0xF0)
			throw new IOException("Not an OMF Library record");
		res = new OmfLibraryRecord(reader);
		res.members = new ArrayList<MemberHeader>();		
		reader.align(res.pageSize);		// Skip padding to get to next page boundary
		type = reader.peekNextByte();
		while(type != (byte)0xF1) {		// Until we see the official "end of library" record
			MemberHeader curheader = new MemberHeader();
			curheader.payloadOffset = reader.getPointerIndex();
			OmfFileHeader fileheader;
			try {
				fileheader = OmfFileHeader.scan(reader, monitor,false);
			} catch (OmfException e) {
				throw new IOException("Could not parse individual object file within archive");
			}
			curheader.name = fileheader.getLibraryModuleName();		// (preferred) name of the object module
			if (curheader.name == null)
				curheader.name = fileheader.getName();				// As a back-up, this is usually the name of the original source
			curheader.machineName = fileheader.getMachineName();
			curheader.translator = fileheader.getTranslator();
			curheader.size = (int)(reader.getPointerIndex() - curheader.payloadOffset);
			res.members.add(curheader);			
			reader.align(res.pageSize);		// Skip padding to get to next page boundary
			type = reader.peekNextByte();
		}
		return res;
	}
}
