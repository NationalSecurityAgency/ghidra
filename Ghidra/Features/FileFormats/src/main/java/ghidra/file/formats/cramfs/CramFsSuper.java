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
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class CramFsSuper implements StructConverter {

	private int magic;
	private int size;
	private int flags;
	private int future;
	private boolean isLE;
	private String signature;
	private CramFsInfo fsid;
	private String name;
	private CramFsInode root;
	private List<CramFsInode> childList = new ArrayList<>();

	/**
	 * Constuctor for the cramfs super block.
	 * @param reader binary reader for the super block.
	 * @throws IOException if there is an error when reading the super block.
	 */
	public CramFsSuper(BinaryReader reader) throws IOException {
		magic = reader.readNextInt();
		size = reader.readNextInt();
		flags = reader.readNextInt();
		future = reader.readNextInt();
		signature = reader.readNextAsciiString(CramFsConstants.HEADER_STRING_LENGTH);
		fsid = new CramFsInfo(reader);
		name = reader.readNextAsciiString(CramFsConstants.HEADER_STRING_LENGTH);
		root = new CramFsInode(reader);
		isLE = reader.isLittleEndian();
		for (int i = 0; i < fsid.getFiles() - 1; i++) {
			childList.add(new CramFsInode(reader));
		}
	}

	/**
	 * Checks to see if the CRAMFS_FLAG_EXT_BLOCK_POINTERS is set or not
	 * @return boolean value for if the flag is set or not
	 */
	public boolean isExtensionsBlockPointerFlagEnabled() {
		return (flags &
			CramFsConstants.CRAMFS_FLAG_EXT_BLOCK_POINTERS) == CramFsConstants.CRAMFS_FLAG_EXT_BLOCK_POINTERS;
	}

	/**
	 * Returns the magic number.
	 * @return the magic number
	 */
	public int getMagic() {
		return magic;
	}

	/**
	 * Returns the size of the super block.
	 * @return the size of the super block
	 */
	public int getSize() {
		return size;
	}

	/**
	 * Returns the super block flags.
	 * @return the super block flags.
	 */
	public int getFlags() {
		return flags;
	}

	/**
	 * Returns the future.
	 * @return the future.
	 */
	public int getFuture() {
		return future;
	}

	/**
	 * Returns if the super block is little endian or not.
	 * @return true if the super block is little endian, or false if not.
	 */
	public boolean isLittleEndian() {
		return isLE;
	}

	/**
	 * Returns the super block signature.
	 * @return the super block signature.
	 */
	public String getSignature() {
		return signature;
	}

	/**
	 * Returns the file system identifier.
	 * @return the file system identifier.
	 */
	public CramFsInfo getFsid() {
		return fsid;
	}

	/**
	 * Returns the name of the super block.
	 * @return the name of the super block.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the root node of the super block.
	 * @return the root node of the super block.
	 */
	public CramFsInode getRoot() {
		return root;
	}

	/**
	 * Returns the childList of the super block.
	 * @return the childList of the super block.
	 */
	public List<CramFsInode> getChildList() {
		return childList;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure struct = new StructureDataType("cramfs_super", 0);
		struct.add(DWORD, "magic", null);
		struct.add(DWORD, "size", null);
		struct.add(DWORD, "flags", null);
		struct.add(DWORD, "future", null);
		struct.add(STRING, CramFsConstants.HEADER_STRING_LENGTH, "signature", null);
		struct.add(fsid.toDataType(), "fsid", null);
		struct.add(STRING, CramFsConstants.HEADER_STRING_LENGTH, "name", null);
		struct.add(root.toDataType(), "root", null);

		return struct;
	}

}
