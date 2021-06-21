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
package ghidra.file.formats.ios.dmg;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

/**
 * Apple Universal Disk Image Format header block, typically located at end of .dmg files
 */
public class UDIFHeader {
	//@formatter:off
	//                                     Offset (hex) Length  Comment
	private int signature;              // 0            4       'koly', 6b 6f 6c 79 or BE 0x6b6f6c79
	private int version;                // 4            4       uint32 - 4
	private int headerSize;             // 8            4       uint32 - should be sizeof header, 512
	private int flags;                  // C            4       uint32
	private long runningDataForkOffset; // 10           8       uint64
	private long dataForkOffset;        // 18           8       uint64 - usually 0
	private long dataForkLength;        // 20           8       uint64 - usually up to xmlOffset
	private long rsrcForkOffset;        // 28           8       uint64
	private long rsrcForkLength;        // 30           8       uint64
	private int segmentNumber;          // 38           4       uint32
	private int segmentCount;           // 3C           4       uint32
	private byte[] segmentID;           // 40           16      uuid
	private int dataChecksumType;       // 50           4       uint32
	private int dataChecksumSize;       // 54           4       uint32
	private int[] dataChecksum;         // 58           128
	private long xmlOffset;             // D8           8       uint64 - probably same as dataForkLength
	private long xmlLength;             // E0           8       uint64 - probably up to this header's offset
	private byte[] reserved;            // E8           120
	private int checksumType;           // 160          4       uint32
	private int checksumSize;           // 164          4       uint32 - count of checksum[] used, up to 32
	private int[] checksum;             // 168          128     uint32[32]
	private int imageVariant;           // 1E8          4       uint32
	private long sectorCount;           // 1EC          8       uint64
	private int reserved2;              // 1F4          4
	private int reserved3;              // 1F8          4
	private int reserved4;              // 1FC          4
	//@formatter:on

	private static final int SIGNATURE_MAGIC_KOLY = 0x6b6f6c79;
	private static final int SIZEOF_UDIF_HEADER = 512;

	/**
	 * Reads a UDIFHeader from the end of the specified ByteProvider
	 * 
	 * @param bp {@link ByteProvider}
	 * @return new UDIFHeader, never null
	 * @throws IOException if io error
	 */
	public static UDIFHeader read(ByteProvider bp) throws IOException {
		return read(bp, bp.length() - SIZEOF_UDIF_HEADER);
	}

	/**
	 * Reads a UDIFHeader from the specified offset of the ByteProvider.
	 * 
	 * @param bp {@link ByteProvider}
	 * @param offset offset (typically 512 bytes from end)
	 * @return new UDIFHeader, never null
	 * @throws IOException if io error
	 */
	public static UDIFHeader read(ByteProvider bp, long offset) throws IOException {
		BinaryReader br = new BinaryReader(bp, false);
		br.setPointerIndex(offset);
		UDIFHeader udif = new UDIFHeader();

		udif.signature = br.readNextInt();
		udif.version = br.readNextInt();
		udif.headerSize = br.readNextInt();
		udif.flags = br.readNextInt();
		udif.runningDataForkOffset = br.readNextLong();
		udif.dataForkOffset = br.readNextLong();
		udif.dataForkLength = br.readNextLong();
		udif.rsrcForkOffset = br.readNextLong();
		udif.rsrcForkLength = br.readNextLong();
		udif.segmentNumber = br.readNextInt();
		udif.segmentCount = br.readNextInt();
		udif.segmentID = br.readNextByteArray(16);
		udif.dataChecksumType = br.readNextInt();
		udif.dataChecksumSize = br.readNextInt();
		udif.dataChecksum = br.readNextIntArray(32);
		udif.xmlOffset = br.readNextLong();
		udif.xmlLength = br.readNextLong();
		udif.reserved = br.readNextByteArray(120);
		udif.checksumType = br.readNextInt();
		udif.checksumSize = br.readNextInt();
		udif.checksum = br.readNextIntArray(32);
		udif.imageVariant = br.readNextInt();
		udif.sectorCount = br.readNextLong();
		udif.reserved2 = br.readNextInt();
		udif.reserved3 = br.readNextInt();
		udif.reserved4 = br.readNextInt();

		return udif;
	}

	/**
	 * Returns true if the fixed fields have valid values
	 * 
	 * @return boolean true if fixed magic / size fields are correct
	 */
	public boolean isValid() {
		return signature == SIGNATURE_MAGIC_KOLY && headerSize == SIZEOF_UDIF_HEADER;
	}

	/**
	 * Returns true if the file offset values in the header are within bounds of the
	 * specified ByteProvider.
	 * 
	 * @param bp {@link ByteProvider}
	 * @return boolean true if file offsets are within range
	 * @throws IOException if io error
	 */
	public boolean hasGoodOffsets(ByteProvider bp) throws IOException {
		return 0 <= dataForkOffset && dataForkOffset < bp.length() &&
			dataForkLength > 0 &&
			dataForkOffset + dataForkLength < bp.length() &&
			0 <= xmlOffset && xmlOffset < bp.length() &&
			xmlLength > 0 &&
			xmlOffset + xmlLength < bp.length();
	}

}
