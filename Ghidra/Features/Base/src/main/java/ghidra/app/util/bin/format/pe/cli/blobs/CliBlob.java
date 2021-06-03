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
package ghidra.app.util.bin.format.pe.cli.blobs;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.exception.AssertException;

/**
 * Describes a blob in the #Blob heap. Format is a coded size then the blob contents.
 * <p>
 * Paraphrasing from ISO 23271:2012 11.24.2.4 (p272):
 * - If the first one byte of the 'blob' is 0bbbbbbb_2: size is bbbbbbb_2 bytes.
 * - {@literal If the first two bytes are 10bbbbbb_2 and x: size is (bbbbbb_2 << 8 + x) bytes.}
 * - {@literal If the first four bytes are 110bbbbb_2, x, y, and z: size is (bbbbb_2<<24 + x<<16 + y<<8 + z) bytes.}
 * The first entry in the heap is the empty 'blob' consisting of a single zero byte.
 */
public class CliBlob implements StructConverter {

	public static final String PATH = "/PE/CLI/Blobs";

	private int streamIndex;
	private BinaryReader reader;

	protected long blobOffset;
	protected long contentsOffset;
	protected int contentsSize;

	/**
	 * Creates a new blob from the given reader, which should be positioned at the start
	 * of the blob.  The reader will be positioned directly after the blob upon completion
	 * of the constructor.
	 * 
	 * @param streamIndex The blob's stream index.
	 * @param reader The reader to use to read the blob.
	 * @throws IOException if there was a problem reading the blob.
	 */
	public CliBlob(int streamIndex, BinaryReader reader) throws IOException {
		this.streamIndex = streamIndex;
		this.reader = reader;

		blobOffset = reader.getPointerIndex();
		contentsSize = parseCodedSize(reader);
		contentsOffset = reader.getPointerIndex();
		reader.setPointerIndex(reader.getPointerIndex() + contentsSize);
	}

	/**
	 * Creates a new blob that is a copy of the given blob.
	 * 
	 * @param blob The blob to copy.
	 */
	protected CliBlob(CliBlob blob) {
		this.streamIndex = blob.streamIndex;
		this.reader = blob.reader;
		this.blobOffset = blob.blobOffset;
		this.contentsSize = blob.contentsSize;
		this.contentsOffset = blob.contentsOffset;
	}

	/**
	 * Creates a new blob that is a copy of the given blob but with a new reader.  
	 * The provided reader must be positioned to the start of the new blob.
	 * 
	 * @param blob The blob to copy.
	 * @param reader The reader to use to read the new blob.  It must be positioned
	 *   to the start of the new blob.
	 */
	protected CliBlob(CliBlob blob, BinaryReader reader) {
		this.streamIndex = blob.streamIndex;
		this.reader = reader;
		this.blobOffset = reader.getPointerIndex();
		this.contentsSize = blob.contentsSize;
		this.contentsOffset = this.blobOffset + this.contentsSize;
	}

	/**
	 * Gets the blob's size in bytes (includes all fields).
	 * 
	 * @return The blob's size in bytes.
	 */
	public int getSize() {
		return (int) (contentsOffset - blobOffset) + contentsSize;
	}

	/**
	 * Gets a new binary reader positioned at the start of this blob's contents.
	 * 
	 * @return A new binary reader positioned at the start of this blob's contents.
	 */
	public BinaryReader getContentsReader() {
		BinaryReader contentsReader =
			new BinaryReader(reader.getByteProvider(), reader.isLittleEndian());
		contentsReader.setPointerIndex(contentsOffset);
		return contentsReader;
	}

	/**
	 * Gets the blob's contents size in bytes.
	 * 
	 * @return The blob's contents size in bytes.
	 */
	public int getContentsSize() {
		return contentsSize;
	}

	/**
	 * Gets the blob's contents.
	 * 
	 * @return the blob's contents.  Could be null if there was a problem reading the 
	 *   contents.
	 */
	public byte[] getContents() {
		long origPointerIndex = reader.getPointerIndex();
		try {
			return reader.readByteArray(contentsOffset, contentsSize);
		}
		catch (IOException e) {
			return null;
		}
		finally {
			reader.setPointerIndex(origPointerIndex);
		}
	}

	/**
	 * Gets the string representation of this blob.
	 * 
	 * @return The string representation of this blob.
	 */
	public String getRepresentation() {
		return "Blob (" + getContentsDataType().getDisplayName() + ")";
	}

	/**
	 * Checks to see whether or not this blob is little endian.
	 * 
	 * @return True if this blob is little endian; false if big endian.
	 */
	public boolean isLittleEndian() {
		return reader.isLittleEndian();
	}

	@Override
	public DataType toDataType() {
		Structure struct = new StructureDataType(new CategoryPath(PATH), "Blob_" + getName(), 0);
		struct.add(getSizeDataType(), "Size", "coded integer - blob size");
		struct.add(getContentsDataType(), getContentsName(), getContentsComment());
		return struct;
	}

	/**
	 * Gets the index into the blob stream of this blob.
	 * 
	 * @return The index into the blob stream of this blob.
	 */
	public int getStreamIndex() {
		return streamIndex;
	}

	/**
	 * Gets the name of this blob.
	 * 
	 * @return The name of this blob.
	 */
	public String getName() {
		return getContentsName() + "_" + streamIndex;
	}

	/**
	 * Gets the name associated with this blob's contents.
	 * 
	 * @return The name associated with this blob's contents.
	 */
	public String getContentsName() {
		return "Generic";
	}

	/**
	 * Gets the data type associated with this blob's contents.
	 * 
	 * @return The data type associated with this blob's contents.
	 */
	public DataType getContentsDataType() {
		return new ArrayDataType(BYTE, this.contentsSize, 1);
	}
	
	/**
	 * Gets the comment associated with this blob's contents.
	 * 
	 * @return The comment associated with this blob's contents.
	 */
	public String getContentsComment() {
		return "Undefined blob contents";
	}

	/**
	 * Gets the proper data type for the blob's size field.
	 * 
	 * @return The proper data type for the blob's size field.
	 */
	public DataType getSizeDataType() {
		int n = (int) (contentsOffset - blobOffset);
		switch (n) {
			case 4:
				return DWORD;
			case 2:
				return WORD;
			case 1:
				return BYTE;
			default:
				throw new AssertException("Unsupported CLI blob size: " + n);
		}
	}

	/**
	 * Parses the coded blob size that the given reader is positioned at.
	 * 
	 * @param reader The reader to use to read the coded blob size.
	 * @return The size of the blob contents in bytes.
	 * @throws IOException if there is a problem reading the coded size field.
	 */
	static int parseCodedSize(BinaryReader reader) throws IOException {
		byte one = reader.readNextByte();
		int size = 0;
		if ((one & 0x80) == 0) {
			size = (one & ~0x80) & 0xff; // 0xff to force this to be positive
		}
		else if ((one & 0xC0) == 0x80) {
			byte two = reader.readNextByte();
			size = (((one & ~0xC0) & 0xff )<< 8) + (two & 0xff); 
		}
		else if ((one & 0xE0) == 0xC0) {
			byte two = reader.readNextByte();
			byte three = reader.readNextByte();
			byte four = reader.readNextByte();
			size = (((one & ~0xE0) & 0xff) << 24) + ((two & 0xff) << 16) + ((three & 0xff) << 8) + (four & 0xff);
		}
		return size;
	}
	
	/* The following methods deal with compressed unsigned/signed integers stored in blobs and signatures -- not the Blob size itself. */
	
	// Uses the test cases in the CLI ISO spec to test our bit manipulation
	public static void testSizeDecoding() {
		System.out.println(decodeCompressedUnsigned((byte)0x03) + " " + decodeCompressedUnsigned((byte)0x7F) + " " + decodeCompressedUnsigned((short)0x8080) + " " + 
				decodeCompressedUnsigned((short)0xAE57) + " " + decodeCompressedUnsigned((short)0xBFFF) + " " + decodeCompressedUnsigned(0xC0004000) + " " + decodeCompressedUnsigned(0xDFFFFFFF) + " ");
		System.out.println(decodeCompressedSigned((byte)0x06) + " " + decodeCompressedSigned((byte)0x7B) + " " + decodeCompressedSigned((short)0x8080) + " " + decodeCompressedSigned((byte)0x01) + " " +  
				decodeCompressedSigned(0xC0004000) + " " + decodeCompressedSigned((short)0x8001) + " " + decodeCompressedSigned(0xDFFFFFFE) + " " + decodeCompressedSigned(0xC0000001) + " ");
	}
	
	private static int getNumberBytesInCodedInt(byte firstByte) {
		if ((firstByte & 0x80) == 0)
			return 1;
		if ((firstByte & 0xc0) == 0x80)
			return 2;
		if ((firstByte & 0xe0) == 0xc0)
			return 4;
		return 0;
	}
	
	/**
	 * Rotates toRotate circularly right using a maximum of bitSize bits for the numeric representation.
	 * Bits must be in the rightmost (least significant) positions.
	 */
	private static int rotateCircularRight(int toRotate, int bitSize) {
		toRotate &= ((1 << bitSize) - 1); // Mask any bits more than bitSize.
		if ((toRotate & 0x1) != 0)
			toRotate |= (1 << bitSize); // Right rotate the least significant bit.
		toRotate = toRotate >> 1;
		if ((toRotate & (1 << (bitSize - 1))) != 0) { // negative number
			toRotate = ~toRotate;
			toRotate += 1;
			toRotate &= ((1 << bitSize) - 1);
			toRotate *= -1;
		}
		return toRotate;
	}
	
	/* For all decoding, note that per ESO 23271.II.23.2, CLI Compressed Integers are physically encoded using big endian byte order. */
	public static int decodeCompressedSigned(byte codedSize) {
		return rotateCircularRight(codedSize, 7);
	}
	
	public static int decodeCompressedSigned(short codedSize) {
		return rotateCircularRight(codedSize, 14);
	}
	
	public static int decodeCompressedSigned(int codedSize) {
		return rotateCircularRight(codedSize, 29);
	}
	
	public static int decodeCompressedUnsigned(byte codedSize) {
		// Header bit is 0, so no need to mask it off.
		return (codedSize & 0xff); // enforce signedness
	}
	
	public static int decodeCompressedUnsigned(short codedSize) {
		codedSize &= (~(0xc000)); // Get rid of header bits "10"
		return (codedSize & 0xffff); // enforce signedness
	}
	
	public static int decodeCompressedUnsigned(int codedSize) {
		codedSize = codedSize & (~(0xe0000000));
		return (codedSize &= 0xffffffff); // enforce signedness
	}

	private static int decodeCompressedInt(BinaryReader reader, boolean signed) throws IOException {
		byte firstByte = reader.peekNextByte();
		boolean isLittleEndian = reader.isLittleEndian();
		reader.setLittleEndian(false);
		int numBytes = getNumberBytesInCodedInt(firstByte);
		int decodedSize = 0;
		switch (numBytes) {
			case 1:
				byte codedByte = reader.readNextByte();
				if (signed)
					decodedSize = decodeCompressedSigned(codedByte);
				else
					decodedSize = decodeCompressedUnsigned(codedByte);
				break;
				
			case 2:
				short codedShort = reader.readNextShort();
				if (signed)
					decodedSize = decodeCompressedSigned(codedShort);
				else
					decodedSize = decodeCompressedUnsigned(codedShort);
				break;
				
			case 4:
				int codedInt = reader.readNextInt();
				if (signed)
					decodedSize = decodeCompressedSigned(codedInt);
				else
					decodedSize = decodeCompressedUnsigned(codedInt);
				break;
				
			default:
				break;
		}
		reader.setLittleEndian(isLittleEndian);
		return decodedSize;
	}
	
	public static int decodeCompressedSignedInt(BinaryReader reader) throws IOException {
		return decodeCompressedInt(reader, true);
	}
	
	public static int decodeCompressedUnsignedInt(BinaryReader reader) throws IOException {
		return decodeCompressedInt(reader, false);
	}
	
	public static DataType getDataTypeForBytes(int numBytes) {
		switch (numBytes) {
			case 1:
				return BYTE;
				
			case 2:
				return WORD;
				
			case 4:
				return DWORD;
				
			default:
				return null;
		}
	}
}
