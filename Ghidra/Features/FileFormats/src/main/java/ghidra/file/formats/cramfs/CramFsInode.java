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
package ghidra.file.formats.cramfs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class CramFsInode implements StructConverter {

	//Packed integers, one 32 bit integer, but two less than 32 bit integers packed into the bit space.
	//__u32 mode: CRAMFS_MODE_WIDTH, id:CRAMFS_UID_WIDTH
	//__u32 size:CRAMFS_SIZE_WIDTH, gid:CRAMFS_GID_WIDTH
	//__u32 namelen:CRAMFS_NAMELEN_WIDTH, offset:CRAMFS_OFFSET_WIDTH
	private int mode;
	private int uid;
	private int size; //Must be a byte array of 3 bytes for 24 bits
	private int gid; //8 bit sized integer
	private int namelen;
	private int offset;
	private String name; //Not explicitly in cramfs_inode
	private long address; //absolute address in file, used for directory traversal.

	public CramFsInode(BinaryReader reader) throws IOException {
		//Before reader reads anything and progresses, get addr for start of inode.
		address = reader.getPointerIndex();
		int modeUID = reader.readNextInt();
		int sizeGID = reader.readNextInt();
		int namelenOffset = reader.readNextInt();

		if (reader.isBigEndian()) {
			modeUID = Integer.reverseBytes(modeUID);
			sizeGID = Integer.reverseBytes(sizeGID);
			namelenOffset = Integer.reverseBytes(namelenOffset);
		}

		//Always read value as little endian
		uid = ((modeUID & 0xffff0000) >> CramFsConstants.CRAMFS_UID_WIDTH) & 0x0000ffff;
		mode = (modeUID & 0x0000ffff);

		gid = ((sizeGID & 0xff000000) >> CramFsConstants.CRAMFS_SIZE_WIDTH) & 0x000000ff;
		size = (sizeGID & 0x00ffffff);

		offset =
			((namelenOffset & 0xffffffc0) >> CramFsConstants.CRAMFS_NAMELEN_WIDTH) & 0x0cffffff;
		namelen = (namelenOffset & 0x0000003f);

		name = reader.readNextAsciiString(namelen * 4);
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		int length = namelen * 4;

		Structure struct = new StructureDataType("cramfs_inode_" + length, 0);
		struct.add(DWORD, "modeUID", null);
		struct.add(DWORD, "sizeGID", null);
		struct.add(DWORD, "namelenOffset", null);

		if (namelen > 0) {
			struct.add(STRING, length, "name", null);
		}
		return struct;
	}

	@Override
	public String toString() {

		StringBuffer buffer = new StringBuffer();
		buffer.append("mode = 0x" + Integer.toHexString(mode) + " 16 MSB, UID = 0x" +
			Integer.toHexString(uid) + " 16 LSB\n");
		buffer.append("size = 0x" + Integer.toHexString(size) + " 24 MSB,  GID = 0x" +
			Integer.toHexString(gid) + " 8 LSB\n");
		buffer.append("namelen = 0x" + Integer.toHexString(namelen) + " 6 MSB, offset = 0x" +
			Integer.toHexString(offset) + " 26 LSB\n");

		if (isFile()) {
			buffer.append("Pointer to data = 0x" + Integer.toHexString(getOffsetAdjusted()) + "\n");
		}

		if (isDirectory()) {
			if (offset == 0) {
				buffer.append("EMPTY DIRECTORY\n");
			}
			else {
				buffer.append(
					"Pointer to next inode = 0x" + Integer.toHexString(getOffsetAdjusted()) + "\n");
			}
		}

		return buffer.toString();
	}

	/**
	 * Returns the mode of the CramFSInode.
	 * @return the mode.
	 */
	public int getMode() {
		return mode;
	}

	/**
	 * Returns the unique identifier of the inode.
	 * @return the unique identifier.
	 */
	public int getUid() {
		return uid;
	}

	/**
	 * Returns the size of the inode.
	 * @return the size.
	 */
	public int getSize() {
		return size;
	}

	/**
	 * Returns the group identifier of the inode.
	 * @return the group identifier.
	 */
	public int getGid() {
		return gid;
	}

	/**
	 * Returns the name length of the inode.
	 * @return the name length.
	 */
	public int getNamelen() {
		return namelen;
	}

	/**
	 * Returns the offset of the inode.
	 * @return the offset.
	 */
	public int getOffset() {
		return offset;
	}

	/**
	 * Returns the name of the inode.
	 * @return the name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the adjusted offset of the inode.
	 * @return the adjusted offset of the inode.
	 */
	public int getOffsetAdjusted() {
		return offset * 4;
	}

	/**
	 * Returns true if the inode is a file.
	 * @return true if the inode is a file.
	 */
	public boolean isFile() {
		return ((mode & 0x8000) != 0);
	}

	/**
	 * Returns true if the inode is a directory.
	 * @return true if the inode is a directory.
	 */
	public boolean isDirectory() {
		return ((mode & 0x4000) != 0);
	}

	/**
	 * Returns the address of the inode.
	 * @return the address of the inode.
	 */
	public long getAddress() {
		return address;
	}
}
