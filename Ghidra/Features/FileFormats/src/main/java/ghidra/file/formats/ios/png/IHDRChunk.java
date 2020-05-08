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
package ghidra.file.formats.ios.png;

import java.io.IOException;
import java.nio.ByteBuffer;

public class IHDRChunk {

	private int length;
	private byte[] chunkID;
	private int imgWidth;
	private int imgHeight;
	private byte bitDepth;
	private byte colorType;
	private byte compressionMethod;
	private byte filterMethod;
	private byte interlaceMethod;
	private int crc32;
	private int bitsPerPalette;
	private int rowFilterBytes;

	/**
	 * Represents the IHDR chunk to process and return the important
	 * metadata within this chunk.
	 * @param chunk the chunk to process as an IHDR chunk
	 * @throws IOException
	 */
	public IHDRChunk(PNGChunk chunk) throws IOException {
		if (chunk.getIDString().equals(CrushedPNGConstants.IHDR_STRING)) {
			this.length = chunk.getLength();
			this.chunkID = chunk.getChunkIDBytes();

			byte[] data = chunk.getData();
			if (data.length == CrushedPNGConstants.IHDR_CHUNK_DATA_SIZE) {
				ByteBuffer buff = ByteBuffer.wrap(data);

				imgWidth = buff.getInt();
				imgHeight = buff.getInt();
				bitDepth = buff.get();
				colorType = buff.get();
				compressionMethod = buff.get();
				filterMethod = buff.get();
				interlaceMethod = buff.get();
			}
			else {
				throw new IOException("Data length " + data.length +
					" does not equal the required length of " +
					CrushedPNGConstants.IHDR_CHUNK_DATA_SIZE);
			}
			this.crc32 = chunk.getCrc32();

			calculateBitsPerPalette();
			calculateRowFilterBytes();
		}
		else {
			throw new IOException("Error processing IHDR Chunk. Invalid chunk name: " +
				chunk.getIDString() + " found");
		}

	}

	/**
	 * <pre>
	   From PNG Specs, http://www.w3.org/TR/PNG-Chunks.html
	   Color    Allowed    Interpretation
	   Type    Bit Depths
	   ------  ----------  ----------------------------------
	   0       1,2,4,8,16  Each pixel is a grayscale sample.
	   
	   2       8,16        Each pixel is an R,G,B triple.
	   
	   3       1,2,4,8     Each pixel is a palette index;
	                       a PLTE chunk must appear.
	   
	   4       8,16        Each pixel is a grayscale sample,
	                       followed by an alpha sample.
	   
	   6       8,16        Each pixel is an R,G,B triple,
	                       followed by an alpha sample.
	* </pre>
	*/
	private void calculateBitsPerPalette() throws IOException {

		switch (colorType) {
			case 0:
				if (bitDepth == 1 || bitDepth == 2 || bitDepth == 4 || bitDepth == 8 ||
					bitDepth == 16) {
					bitsPerPalette = bitDepth;
					break;
				}
			case 2:
				if (bitDepth == 8 || bitDepth == 16) {
					bitsPerPalette = 3 * bitDepth;
					break;
				}
			case 3:
				if (bitDepth == 1 || bitDepth == 2 || bitDepth == 4 || bitDepth == 8) {
					bitsPerPalette = bitDepth;
					break;
				}
			case 4:
				if (bitDepth == 8 || bitDepth == 16) {
					bitsPerPalette = 4 * bitDepth;
					break;
				}
			case 6:
				if (bitDepth == 8 || bitDepth == 16) {
					bitsPerPalette = 4 * bitDepth;
					break;
				}
			default:
				throw new IOException("Unknown color type: " + colorType);
		}
	}

	private void calculateRowFilterBytes() {
		if (interlaceMethod == CrushedPNGConstants.ADAM7_INTERLACE) {
			//Msg.debug(this, "Adam7 interlacing");

			for (int pass = 0; pass < CrushedPNGConstants.STARTING_ROW.length; pass++) {
				int height =
					(imgHeight - CrushedPNGConstants.STARTING_ROW[pass] + CrushedPNGConstants.ROW_INCREMENT[pass] - 1) /
						CrushedPNGConstants.ROW_INCREMENT[pass];
				rowFilterBytes += height;
			}

		} else {
			rowFilterBytes = imgHeight;
		}
	}

	public int getImgWidth() {
		return imgWidth;
	}

	public int getImgHeight() {
		return imgHeight;
	}

	public byte getBitDepth() {
		return bitDepth;
	}

	public byte getColorType() {
		return colorType;
	}

	public byte getCompressionMethod() {
		return compressionMethod;
	}

	public byte getFilterMethod() {
		return filterMethod;
	}

	public byte getInterlaceMethod() {
		return interlaceMethod;
	}

	public int getBitsPerPalette() {
		return bitsPerPalette;
	}

	public int getBytesPerPalette() {
		return (bitsPerPalette + 7) / 8;
	}

	public int getBytesPerLine() {
		return (imgWidth * bitsPerPalette + 7) / 8;
	}

	public int getRowFilterBytes() {
		return rowFilterBytes;

	}

	public byte[] getChunkBytes() {
		return ByteBuffer.allocate(CrushedPNGConstants.IHDR_CHUNK_DATA_SIZE).putInt(imgWidth).putInt(
			imgHeight).put(bitDepth).put(colorType).put(compressionMethod).put(filterMethod).array();
	}

	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();

		buff.append("Data Length: " + length + "\n");
		buff.append("Chunk ID: " + new String(chunkID) + "\n");
		buff.append("Width: " + imgWidth + "\n");
		buff.append("Height: " + imgHeight + "\n");
		buff.append("Bit Depth: " + bitDepth + "\n");
		buff.append("Color Type: " + colorType + "\n");
		buff.append("Compression Method: " + compressionMethod + "\n");
		buff.append("Filter Method: " + filterMethod + "\n");
		buff.append("Interlace Method: " + interlaceMethod + "\n");
		buff.append("Bits Per Palette: " + bitsPerPalette + "\n");
		buff.append("Bytes Per Line: " + (imgWidth * bitsPerPalette + 7) / 8 + "\n");
		buff.append("CRC32: " + crc32 + "\n");

		return buff.toString();
	}
}
