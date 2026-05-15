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
package ghidra.file.formats.yaffs2;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.util.NumericUtilities;

/**
 * <pre>
 * struct yaffs_obj_hdr  // Length: 512 (0x200)
 * {
 *   u32                type
 *   u32                parent_obj_id
 *   u16                sum_no_longer_used
 *   YCHAR[256]         name
 *   u32                yst_mode
 *   u32                yst_uid
 *   u32                yst_gid
 *   u32                yst_atime
 *   u32                yst_mtime
 *   u32                yst_ctime
 *   u32                file_size_low
 *   int                equiv_id
 *   YCHAR[160]         alias
 *   u32                yst_rdev
 *   u32[2]             win_ctime
 *   u32[2]             win_atime
 *   u32[2]             win_mtime
 *   u32                inband_shadowed_obj_id
 *   u32                inband_is_shrink
 *   u32                file_size_high
 *   u32[1]             reserved
 *   int                shadows_obj
 *   u32                is_shrink
 * }
 * </pre>
 */
public class YAFFS2Header {

	/**
	 * Reads a YAFFS2 objhdr struct.
	 * 
	 * @param br stream to read from
	 * @return new YAFFS2Header, never null
	 * @throws IOException if error reading
	 */
	public static YAFFS2Header read(BinaryReader br) throws IOException {
		YAFFS2Header result = new YAFFS2Header();
		result.objectType = br.readNextInt();
		result.parentObjectId = br.readNextUnsignedInt();
		result.checksum = br.readNextShort();
		result.fileName = readNextYaffs2String(br, 256);
		br.align(4 /*sizeof(int) */);
		result.ystMode = br.readNextUnsignedInt();
		result.ystUId = br.readNextUnsignedInt();
		result.ystGId = br.readNextUnsignedInt();
		result.ystATime = br.readNextUnsignedInt();
		result.ystMTime = br.readNextUnsignedInt();
		result.ystCTime = br.readNextUnsignedInt();
		result.fileSizeLow = br.readNextUnsignedInt();
		result.equivId = br.readNextUnsignedInt();
		result.aliasFileName = readNextYaffs2String(br, 160);
		result.ystRDev = br.readNextUnsignedInt();
		result.winCTime = br.readNextIntArray(2);
		result.winATime = br.readNextIntArray(2);
		result.winMTime = br.readNextIntArray(2);
		result.inbandObjId = br.readNextUnsignedInt();
		result.inbandIsShrink = br.readNextUnsignedInt();
		result.fileSizeHigh = br.readNextUnsignedInt();
		br.readNextInt(); // reserved
		result.shadowsObject = br.readNextUnsignedInt();
		result.isShrink = br.readNextUnsignedInt();
		// assert(br.index == +512)
		return result;
	}

	// header objects
	private long objectType;
	private long parentObjectId;
	private short checksum;
	private String fileName;
	private long ystMode;
	private long ystUId;
	private long ystGId;
	private long ystATime;
	private long ystMTime;
	private long ystCTime;
	private long fileSizeLow;
	private long equivId;
	private String aliasFileName;
	private long ystRDev;
	private int[] winCTime;
	private int[] winATime;
	private int[] winMTime;
	private long inbandObjId;
	private long inbandIsShrink;
	private long fileSizeHigh;
	private long shadowsObject;
	private long isShrink;

	public YAFFS2Header() {
	}

	/**
	 * Returns the number of data pages that will follow this page.
	 * 
	 * @param pageSize size of pages in this fs
	 * @return the number of data pages that will follow this page
	 */
	public long getDataPageCount(int pageSize) {
		return getObjectTypeEnum() == YAFFS2ObjectType.File
				? NumericUtilities.getUnsignedAlignedValue(calcFileSize(), pageSize) / pageSize
				: 0;
	}

	/**
	 * Returns true if the data in this object appears valid
	 * 
	 * @param bp stream that contains the entire yaffs2 image
	 * @return boolean true if the data in this object appears valid
	 */
	public boolean isValid(ByteProvider bp) {
		YAFFS2ObjectType ote = getObjectTypeEnum();
		if (ote == YAFFS2ObjectType.File) {
			long filesize = calcFileSize();
			if (filesize < 0 || filesize > bp.length()) {
				return false;
			}
		}
		return ote != YAFFS2ObjectType.INVALID;
	}

	public long getObjectType() {
		return objectType;
	}

	public YAFFS2ObjectType getObjectTypeEnum() {
		return YAFFS2ObjectType.parse(objectType);
	}

	public short getChecksum() {
		return checksum;
	}

	public String getName() {
		return fileName;
	}

	public long getYstMode() {
		return ystMode;
	}

	public long getYstUId() {
		return ystUId;
	}

	public long getYstGId() {
		return ystGId;
	}

	public long getYstATime() {
		return ystATime;
	}

	public long getYstMTime() {
		return ystMTime;
	}

	public long getYstCTime() {
		return ystCTime;
	}

	public long getSize() {
		return fileSizeLow;
	}

	public long getTotalSize() {
		return fileSizeLow | (fileSizeHigh << 32L);
	}

	public long getEquivId() {
		return equivId;
	}

	public String getAliasFileName() {
		return aliasFileName;
	}

	public long getYstRDev() {
		return ystRDev;
	}

	public int[] getWinCTime() {
		return winCTime;
	}

	public int[] getWinATime() {
		return winATime;
	}

	public int[] getWinMTime() {
		return winMTime;
	}

	public long getInbandObjId() {
		return inbandObjId;
	}

	public long getInbandIsShrink() {
		return inbandIsShrink;
	}

	public long getFileSizeHigh() {
		return fileSizeHigh;
	}

	public long calcFileSize() {
		return fileSizeLow |
			(fileSizeHigh != NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG ? fileSizeHigh : 0);
	}

	public long getShadowsObject() {
		return shadowsObject;
	}

	public long getIsShrink() {
		return isShrink;
	}

	public long getParentObjectId() {
		return parentObjectId;
	}

	static String readNextYaffs2String(BinaryReader br, int len) throws IOException {
		// truncate both trailing 0's and FF's.
		byte[] bytes = br.readNextByteArray(len);
		int i = bytes.length - 1;
		while (i >= 0 && (bytes[i] == 0 || bytes[i] == -1)) {
			i--;
		}
		return new String(bytes, 0, i + 1, StandardCharsets.UTF_8);
	}

}
