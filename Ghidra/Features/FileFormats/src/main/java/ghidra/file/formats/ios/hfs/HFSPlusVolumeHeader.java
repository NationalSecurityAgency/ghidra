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
package ghidra.file.formats.ios.hfs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

/**
 * Apple HFS+ volume header.
 * <p>
 * See https://developer.apple.com/library/archive/technotes/tn/tn1150.html#VolumeHeader
 * <p>
 * Fields are BigEndian
 */
public class HFSPlusVolumeHeader {
	//@formatter:off
	//                                     Offset (hex) Length  Comment
	private short signature;              // 0            2     48 2b, "H+"
	private short version;                // 2            2     4=HFS+, 5=HFSX
	private int attributes;               // 4            4
	private int lastMountedVersion;       // 8            4     '10.0' string
	private int journalInfoBlock;         // C            4
	
	private int createDate;               // 10           4
	private int modifyDate;               // 14           4
	private int backupDate;               // 18           4
	private int checkedDate;              // 1C           4
	
	private int fileCount;                // 20           4
	private int folderCount;              // 24           4
	
	private int blockSize;                // 28           4     0x1000=4096
	private int totalBlocks;              // 2C           4     blockSize*totalBlocks should equal vol size
	private int freeBlocks;               // 30           4
	
	private int nextAllocation;           // 34           4
	private int rsrcClumpSize;            // 38           4
	private int dataClumpSize;            // 3C           4
	private int nextCatalogID;            // 40           4 
	
	private int writeCount;               // 44           4
	private long encodingsBitmap;         // 48           8
	
	private int[] finderInfo;             // 50           32    uint32[8]
	
	private byte[] rawForkData;           // 70           400
    //HFSPlusForkData     allocationFile; // 70           80
    //HFSPlusForkData     extentsFile;    // C0           80
    //HFSPlusForkData     catalogFile;    // 110          80
    //HFSPlusForkData     attributesFile; // 160          80
    //HFSPlusForkData     startupFile;    // 1B0          80
	//@formatter:on

	private static final int HFSPLUS_SIGNATURE_MAGIC = 0x482b; // "H+"
	private static final int HFSX_SIGNATURE_MAGIC = 0x4858; // "HX"
	private static final int HFSPLUS_VERSION = 4;
	private static final int HFSX_VERSION = 5;
	private static final int SIZEOF_HEADER = 512;
	private static final int DEFAULT_OFFSET = 1024;

	public static boolean probe(ByteProvider provider) {
		try {
			if (provider.length() < DEFAULT_OFFSET + SIZEOF_HEADER) {
				return false;
			}
			HFSPlusVolumeHeader header = read(provider);
			return header.isValid() && header.hasGoodVolumeInfo(provider);
		}
		catch (IOException e) {
			return false;
		}
	}

	public static HFSPlusVolumeHeader read(ByteProvider provider) throws IOException {
		return read(provider, DEFAULT_OFFSET);
	}

	public static HFSPlusVolumeHeader read(ByteProvider provider, long offset) throws IOException {
		BinaryReader reader = new BinaryReader(provider, false /*BE*/);
		reader.setPointerIndex(offset);
		HFSPlusVolumeHeader result = new HFSPlusVolumeHeader();
		result.signature = reader.readNextShort();
		result.version = reader.readNextShort();
		result.attributes = reader.readNextInt();
		result.lastMountedVersion = reader.readNextInt();
		result.journalInfoBlock = reader.readNextInt();
		
		result.createDate = reader.readNextInt();
		result.modifyDate = reader.readNextInt();
		result.backupDate = reader.readNextInt();
		result.checkedDate = reader.readNextInt();
		
		result.fileCount = reader.readNextInt();
		result.folderCount = reader.readNextInt();
		
		result.blockSize = reader.readNextInt();
		result.totalBlocks = reader.readNextInt();
		result.freeBlocks = reader.readNextInt();
		
		result.nextAllocation = reader.readNextInt();
		result.rsrcClumpSize = reader.readNextInt();
		result.dataClumpSize = reader.readNextInt();
		result.nextCatalogID = reader.readNextInt();

		result.writeCount = reader.readNextInt();
		result.encodingsBitmap = reader.readNextLong();

		result.finderInfo = reader.readNextIntArray(8);

		result.rawForkData = reader.readNextByteArray(400);

		return result;
	}

	public boolean isValid() {
		return signature == HFSPLUS_SIGNATURE_MAGIC && version == HFSPLUS_VERSION &&
			isGoodBlockSize(blockSize);
	}

	private static boolean isGoodBlockSize(int bs) {
		return bs > 0 && bs % 512 == 0;
	}

	public boolean hasGoodVolumeInfo(ByteProvider bp) throws IOException {
		long calculatedSize = blockSize * totalBlocks;
		// NOTE: can't compare with exact equals-to provider size because an extra 16 bytes
		// are present in examples extracted from firmware images
		return bp.length() >= calculatedSize;
	}
}
