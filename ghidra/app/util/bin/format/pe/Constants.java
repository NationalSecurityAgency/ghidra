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
package ghidra.app.util.bin.format.pe;
/**
 * Constants used in the data structures of the PE.
 * 
 * 
 */
public interface Constants {
	/**A 64-bit flag.*/
	public final static long IMAGE_ORDINAL_FLAG64 = 0x8000000000000000L;
	/**A 32-bit flag.*/
	public final static long IMAGE_ORDINAL_FLAG32 =         0x80000000L;

	/**
	 * The magic number for PE files..
	 */
	public final static int IMAGE_NT_SIGNATURE =  0x00004550; // PE00
	/**
	 * The magic number for OS/2 files.
	 */
	public final static int IMAGE_OS2_SIGNATURE = 0x454E; // NE
	/**
	 * The magic number for little endian OS/2 files.
	 */
	public final static int IMAGE_OS2_SIGNATURE_LE = 0x454C; // LE
	/**
	 * The magic number for VXD files.
	 */
	public final static int IMAGE_VXD_SIGNATURE = 0x454C; // LE

	/**
	 * The 32-bit optional header magic number.
	 */
	public final static short IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
	/**
	 * The 64-bit optional header magic number.
	 */
	public final static short IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;
	/**
	 * The ROM optional header magic number.
	 */
	public final static short IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107;


	/**
	 * The size of the ROM optional header.
	 */
	public final static int IMAGE_SIZEOF_ROM_OPTIONAL_HEADER = 56;
	/**
	 * The size of the standard optional header.
	 */
	public final static int IMAGE_SIZEOF_STD_OPTIONAL_HEADER = 28;
	/**
	 * The size of the 32-bit optional header, in bytes.
	 */
	public final static int IMAGE_SIZEOF_NT_OPTIONAL32_HEADER =  224;
	/**
	 * The size of the 64-bit optional header, in bytes.
	 */
	public final static int IMAGE_SIZEOF_NT_OPTIONAL64_HEADER =  240;


	/**
	 * The size of the archive start header.
	 */
	public final static byte IMAGE_ARCHIVE_START_SIZE = 8;
	/**
	 * The archive start magic value.
	 */
	public final static String IMAGE_ARCHIVE_START = "!<arch>\n";
	/**
	 * The archive end magic value.
	 */
	public final static String IMAGE_ARCHIVE_END = "`\n";
	/**
	 * The archive padding.
	 */
	public final static String IMAGE_ARCHIVE_PAD = "\n";
	/**
	 * The archive linker member.
	 */
	public final static String IMAGE_ARCHIVE_LINKER_MEMBER = "/               ";
	/**
	 * The archive long names member.
	 */
	public final static String IMAGE_ARCHIVE_LONGNAMES_MEMBER = "//              ";

}
