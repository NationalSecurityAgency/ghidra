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

/**
* @see <a href="https://github.com/torvalds/linux/tree/master/fs/cramfs">/fs/cramfs</a>
*/
public final class CramFsConstants {
	public static final int HEADER_STRING_LENGTH = 16;
	public static final int MAGIC = 0x28cd3d45;

	/**
	 * Constant size of an inode in bytes in memory.
	 */
	public static final int INODE_SIZE = 12;

	/**
	 * Flag as described in cramfs_fs.h.
	 */
	public static final int CRAMFS_FLAG_EXT_BLOCK_POINTERS = 0x00000800;

	/** 
	 * Documentation points to this being the default size 
	 * provide option for user if they know the block size.
	 */
	public static final int DEFAULT_BLOCK_SIZE = 4096;
	public static final int BLOCK_POINTER_SIZE = 4;
	public static final int ZLIB_MAGIC_SIZE = 2;

	/**
	 * Width of various bitfields in struct {@link CramFsInode}
	 */
	public static final int CRAMFS_MODE_WIDTH = 16;
	public static final int CRAMFS_UID_WIDTH = 16;
	public static final int CRAMFS_SIZE_WIDTH = 24;
	public static final int CRAMFS_GID_WIDTH = 8;
	public static final int CRAMFS_NAMELEN_WIDTH = 6;
	public static final int CRAMFS_OFFSET_WIDTH = 26;

}
