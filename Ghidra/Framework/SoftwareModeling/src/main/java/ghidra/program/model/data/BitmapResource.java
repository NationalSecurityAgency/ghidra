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
package ghidra.program.model.data;

import java.awt.Transparency;
import java.awt.color.ColorSpace;
import java.awt.image.*;
import java.io.IOException;

import javax.swing.ImageIcon;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

// FIXME: Implementation does not properly handle multiple image data planes

public class BitmapResource {
	private static final int BOTTOM_UP = 1;

	// TODO
	// private static final int TOP_DOWN = 2;
	protected int size;

	private int width; // reflects value in header - use getWidth() for real width

	private int planes;

	private int bitCount;

	private int compression;

	private int xPelsPerMeter;

	private int yPelsPerMeter;

	private int clrUsed;

	private int clrImportant;

	protected int sizeImage;

	protected int rawSizeImage = -1;

	private int imageDataOffset;

	protected int height; // reflects value in header - use getHeight() for real height

	protected int rowOrder = BOTTOM_UP;

	/* constants for the biCompression field */
	private final static int BI_RGB = 0;
	private final static int BI_RLE8 = 1;
	private final static int BI_RLE4 = 2;

//	private final static int BI_BITFIELDS = 3;
//	private final static int BI_JPEG = 4;
//	private final static int BI_PNG = 5;
/*  from MSDN online:
	BI_RGB = 0x0000,
    BI_RLE8 = 0x0001,
    BI_RLE4 = 0x0002,
	BI_BITFIELDS = 0x0003,
	BI_JPEG = 0x0004,
	BI_PNG = 0x0005,
	BI_CMYK = 0x000B,
	BI_CMYKRLE8 = 0x000C,
	BI_CMYKRLE4 = 0x000D	   
*/

	/**
	 * @throws IOException 
	 * 
	 */
	public BitmapResource(MemBuffer buf) throws IOException {
		initialize(buf);
	}

	private void initialize(MemBuffer buf) throws IOException {
		try {
			size = buf.getInt(0);
			width = buf.getInt(4);
			height = buf.getInt(8);
			planes = buf.getShort(12);
			bitCount = buf.getShort(14);
			compression = buf.getInt(16);
			sizeImage = buf.getInt(20);
			xPelsPerMeter = buf.getInt(24);
			yPelsPerMeter = buf.getInt(28);
			clrUsed = buf.getInt(32);
			clrImportant = buf.getInt(36);
			imageDataOffset = size + getColorMapLength();
		}
		catch (MemoryAccessException e) {
			throw new IOException("Truncated header for bitmap at " + buf.getAddress());
		}
		if (bitCount < 0 || width < 0 || height < 0 || bitCount > 32 || width > 4096 ||
			height > 4096) {
			throw new IOException("Invalid dimensions for bitmap at " + buf.getAddress());
		}
		if ((clrUsed > (int) Math.pow(2.0, bitCount)) || (clrUsed > 0x10000) ||
			((clrUsed == 0) && (bitCount > 32))) {
			throw new IOException("Invalid colormap dimensions for bitmap at " +
				buf.getAddress());
		}
		int sz = width * height * bitCount / 0x10; // 0x10 = bits/byte * 2 (possible mask)
		if (sz < 0 || sizeImage < 0) {
			throw new IOException("Invalid size for bitmap at " + buf.getAddress());
		}

		//The following check was keeping an image from rendering
		//Removing it doesn't seem to be causing any problems but keep it around for awhile to make sure
//		if (sizeImage > 0 && sz > sizeImage) {
//			throw new IOException("Invalid size for bitmap at " + buf.getAddress());
//		}

		try {
			BitmapDecompressResult decompress =
				decompress(buf, imageDataOffset, false, getImageDataSize());
			rawSizeImage = decompress.rawDataSize;
		}
		catch (MemoryAccessException e) {
			throw new IOException("Image data read error for bitmap at " + buf.getAddress());
		}
	}

	/**
	 * @return int size of mask section in bytes
	 */
	public int getMaskLength() {
		return 0;
	}

	public int getSize() {
		return size;
	}

	public int getWidth() {
		return width;
	}

	public int getHeight() {
		return height;
	}

	public int getPlanes() {
		return planes;
	}

	public int getBitCount() {
		return bitCount;
	}

	public int getCompression() {
		return compression;
	}

	/**
	 * Get the raw image data size as contained within this resource.  If compressed, 
	 * this will be smaller than the value returned by {@link #getImageDataSize() } which reflects
	 * the uncompressed size.
	 * @return raw image data size
	 */
	public int getRawSizeImage() {
		return rawSizeImage;
	}

	/**
	 * Returns the uncompressed image data size.  The default implementation will
	 * return the image data size specified by the header if non-zero, otherwize
	 * a computed data length will be returned based upon getHeight(), getWidth() and
	 * getBitCount().
	 * @return image data size
	 */
	public int getImageDataSize() {
		if (sizeImage == 0) {
			sizeImage = getComputedUncompressedImageDataSize();
		}
		return sizeImage;
	}

	/**
	 * Compute the uncompressed image data size based upon getHeight(), getWidth() and
	 * getBitCount().
	 * @return computed image data size
	 */
	protected int getComputedUncompressedImageDataSize() {
		return getBytesPerLine() * getHeight();
	}

	/**
	 * Compute the uncompressed image data size for a single line based upon getWidth() and
	 * getBitCount().
	 * @return computed image data size for single line
	 */
	private int getBytesPerLine() {
		int lineLen = getWidth() * getBitCount();

		if (getBitCount() == 1) {
			lineLen = lineLen / 8;
		}
		else if (getBitCount() == 4) {
			lineLen = (lineLen + 4) / 8;
		}
		else if (getBitCount() == 24) {
			lineLen = lineLen / 8;
		}
		else {
			lineLen = lineLen / 8;
		}
		if ((lineLen % 4) != 0) {
			lineLen = lineLen + (4 - (lineLen % 4));
		}
		return lineLen;
	}

	public int getXPelsPerMeter() {
		return xPelsPerMeter;
	}

	public int getYPelsPerMeter() {
		return yPelsPerMeter;
	}

	public int getClrUsed() {
		if (clrUsed == 0) {
			clrUsed = (int) Math.pow(2.0, bitCount);
		}
		return clrUsed;
	}

	public int getClrImportant() {
		return clrImportant;
	}

	public byte[] getPixelData(MemBuffer buf) {
		byte[] rawPixels = new byte[this.getImageDataSize()];
		if (buf.getBytes(rawPixels, size + getColorMapLength()) != rawPixels.length) {
			return new byte[0];
		}
		return rawPixels;
	}

	public int[] getRGBData(MemBuffer buf) {
		byte[] rawCmap = new byte[this.getColorMapLength()];
		if (buf.getBytes(rawCmap, size) != rawCmap.length) {
			return new int[0];
		}

		int[] cmap = new int[getClrUsed()];
		for (int i = 0; i < cmap.length; i++) {
			cmap[i] = (rawCmap[i * 4 + 2] & 0xff) << 16;
			cmap[i] += ((rawCmap[i * 4 + 1]) & 0xff) << 8;
			cmap[i] += ((rawCmap[i * 4 + 0]) & 0xff);
		}
		return cmap;
	}

	public int[] getColorMap(MemBuffer buf) {
		return null;
	}

	/**
	 * @return int
	 */
	public int getColorMapLength() {
		if (bitCount == 32 || bitCount == 24) {
			return 0;
		}
		return getClrUsed() * 4;
	}

	/**
	 * @return DataImage
	 */
	public DataImage getDataImage(MemBuffer buf) {
		if (bitCount == 1) {
			return getOnePlaneImage(buf);
		}
		if (bitCount == 4) {
			return getFourPlaneImage(buf);
		}
		if (bitCount == 8) {
			return getEightPlaneImage(buf);
		}
		if (bitCount == 24) {
			return get18PlaneImage(buf);
		}
		if (bitCount == 32) {
			return get32PlaneImage(buf);
		}
		return null;
	}

	private static class BitmapDataImage extends DataImage {

		private final BufferedImage image;

		BitmapDataImage(BufferedImage image) {
			this.image = image;
		}

		@Override
		public ImageIcon getImageIcon() {
			return ResourceManager.getImageIconFromImage("Bitmap Data Image", image);
		}

		@Override
		public String getImageFileType() {
			return "bmp";
		}
	}

	/**
	 * @param buf
	 * @return DataImage
	 */
	protected DataImage get32PlaneImage(MemBuffer buf) {
		// create the color model
		ColorSpace cs = ColorSpace.getInstance(ColorSpace.CS_sRGB);
		int[] nBits = { 8, 8, 8, 8 };
		int[] bOffs = { 0, 1, 2, 3 };
		ColorModel colorModel =
			new ComponentColorModel(cs, nBits, true, false, Transparency.TRANSLUCENT,
				DataBuffer.TYPE_BYTE);
		int w = getWidth();
		int h = getHeight();
		WritableRaster raster =
			Raster.createInterleavedRaster(DataBuffer.TYPE_BYTE, w, h, w * 4, 4, bOffs, null);

		// create the image

		BufferedImage image =
			new BufferedImage(colorModel, raster, colorModel.isAlphaPremultiplied(), null);

		byte[] dbuf = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
		getPixelData(buf, dbuf);
		return new BitmapDataImage(image);
	}

	/**
	 * @param buf
	 * @return DataImage
	 */
	protected DataImage get18PlaneImage(MemBuffer buf) {
		// create the color model
		ColorSpace cs = ColorSpace.getInstance(ColorSpace.CS_sRGB);
		int[] nBits = { 8, 8, 8 };
		int[] bOffs = { 2, 1, 0 };
		ColorModel colorModel =
			new ComponentColorModel(cs, nBits, false, false, Transparency.OPAQUE,
				DataBuffer.TYPE_BYTE);
		int w = getWidth();
		int h = getHeight();
		WritableRaster raster =
			Raster.createInterleavedRaster(DataBuffer.TYPE_BYTE, w, h, w * 3, 3, bOffs, null);

		// create the image

		BufferedImage image =
			new BufferedImage(colorModel, raster, colorModel.isAlphaPremultiplied(), null);

		byte[] dbuf = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
		getPixelData(buf, dbuf);
		return new BitmapDataImage(image);
	}

	/**
	 * @param buf
	 * @return DataImage
	 */
	protected DataImage getEightPlaneImage(MemBuffer buf) {
		// create the color model
		IndexColorModel model =
			new IndexColorModel(8, getClrUsed(), getRGBData(buf), 0, false, -1,
				DataBuffer.TYPE_BYTE);

		// create the image
		BufferedImage image =
			new BufferedImage(getWidth(), getHeight(), BufferedImage.TYPE_BYTE_INDEXED, model);
		byte[] dbuf = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
		getPixelData(buf, dbuf);
		return new BitmapDataImage(image);
	}

	/**
	 * @param buf
	 * @return DataImage
	 */
	protected DataImage getFourPlaneImage(MemBuffer buf) {
		// create the color model
		int[] colormapData = getRGBData(buf);
		IndexColorModel model =
			new IndexColorModel(4, getClrUsed(), colormapData, 0, false, -1, DataBuffer.TYPE_BYTE);

		// create the image
		BufferedImage image =
			new BufferedImage(getWidth(), getHeight(), BufferedImage.TYPE_BYTE_BINARY, model);
		byte[] dbuf = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
		getPixelData(buf, dbuf);
		return new BitmapDataImage(image);
	}

	/**
	 * @param buf
	 * @return DataImage
	 */
	protected DataImage getOnePlaneImage(MemBuffer buf) {
		// create the color model

		// create the image

		BufferedImage image =
			new BufferedImage(getWidth(), getHeight(), BufferedImage.TYPE_BYTE_BINARY);
		byte[] dbuf = ((DataBufferByte) image.getRaster().getDataBuffer()).getData();
		getPixelData(buf, dbuf);
		return new BitmapDataImage(image);
	}

	/**
	 * @param buf
	 * @param dbuf
	 */
	protected void getPixelData(MemBuffer buf, byte[] dbuf) {
//		int height = getHeight();

		int bytesPerLine = getBytesPerLine();
//		switch (getBitCount()) {
//		case 32:
//			bytesPerLine = getWidth() * 4;
//			break;
//		case 8:
//			bytesPerLine = getWidth();
//			break;
//		case 4:
//			bytesPerLine = (getWidth() + 1) / 2;
//			break;
//		case 1:
//			bytesPerLine = (getWidth() + 7) / 8;
//			break;
//		}
		//byte[] imageData = getPixelData(buf);
		//imageData = decompress(imageData, width, height);

		BitmapDecompressResult decompress;
		try {
			decompress = decompress(buf, imageDataOffset, true, getImageDataSize());
		}
		catch (MemoryAccessException e) {
			// ignore - should be caught by constructor initialization
			return;
		}

		byte[] imageData = decompress.decompressedImageData;

		int h = getHeight();

		if (this.compression != BI_RGB) {
			bytesPerLine = ((imageData.length) / h);
		}

		if (imageData.length == 0) {
			return;
		}
		if (rowOrder == BOTTOM_UP) {
			for (int i = 0; i < h; i++) {
				int offset = i * bytesPerLine;
				int destIndex = (h - i - 1) * (dbuf.length / h);
				System.arraycopy(imageData, offset, dbuf, destIndex, dbuf.length / h);
				// buf.getMemory().getBytes(addr, dbuf, destIndex, bytesPerLine);
			}
		}
		// else TODO
	}

	private static class BitmapDecompressResult {
		final int rawDataSize;
		final int decompressedDataSize;
		final byte[] decompressedImageData; // may be null if not decompressed

		BitmapDecompressResult(int rawDataSize, int decompressedDataSize,
				byte[] decompressedImageData) {
			this.rawDataSize = rawDataSize;
			this.decompressedDataSize = decompressedDataSize;
			this.decompressedImageData = decompressedImageData;
		}
	}

	/**
	 * Process compressed image data contained within the specified memory buffer.
	 * @param mem memory buffer positioned to start of compressed image data
	 * @param out optional decompressed image data output stream
	 * @return BitmapDecompressResult result of decompression processing where decompressedImageData
	 * will only be filled-in if returnDecompressedData is true;
	 * @throws MemoryAccessException if decompression fails due to memory constraint
	 */
	private BitmapDecompressResult decompress(MemBuffer buf, int offset,
			boolean returnDecompressedData, int maxCompressedDataLength)
					throws MemoryAccessException {

		//private byte[] decompress(byte[] imageData, int width1, int height1) {

		int rawDataSize = 0;
		int decompressedDataSize = 0;
		byte[] decompressedData = null;

		int h = getHeight();
		int w = getWidth();

		int maxBufferOffset = offset + maxCompressedDataLength;

		if (compression == BI_RGB) {
			rawDataSize = getImageDataSize();
			decompressedDataSize = rawDataSize;
			if (returnDecompressedData) {
				decompressedData = new byte[rawDataSize];
				buf.getBytes(decompressedData, offset);
			}
		}
		// Real size of image...
		else if (compression == BI_RLE4) {
			int x = 0;
			int y = 0;
			int byteWidth = (w + 1) / 2;
			decompressedDataSize = byteWidth * h;
			if (returnDecompressedData) {
				decompressedData = new byte[decompressedDataSize];
			}
			int readOffset = offset;
			try {
				while (true) {
					if (readOffset >= maxBufferOffset) {
						throw new MemoryAccessException(
							"Bitmap resource decompression exceeded memory constraint at " +
								buf.getAddress());
					}
					int val = buf.getByte(readOffset++);
					if (val == 0) { // escape
						val = buf.getByte(readOffset++);
						if (val == 1) {
							break; // End of Bitmap - break from loop
						}
						switch (val) {
							case 0: // EOL
								x = 0;
								y++;
								break;
							case 1: // End of Bitmap
								throw new AssertException(); // already handled
							case 2: // Delta
								int xdelta = buf.getByte(readOffset++) & 0xff;
								int ydelta = buf.getByte(readOffset++) & 0xff;
								x += xdelta;
								y += ydelta;
								break;
							default: // Absolute
								int numFollow = val & 0xff;
								if (decompressedData != null) {
									byte[] bytes = new byte[numFollow / 2];
									buf.getBytes(bytes, readOffset);
									System.arraycopy(bytes, 0, decompressedData,
										y * byteWidth + x / 2, bytes.length);
									x += numFollow;
								}
								readOffset += (numFollow + 1) / 2;
								readOffset += (readOffset % 2);
								break;
						}
						continue;
					}
					int run = val;
					val = buf.getByte(readOffset++);
					if (decompressedData != null) {
						for (int j = 0; j < run; j++) {
							if (x >= w || y >= h) {
								break;
							}
							int cval = decompressedData[y * byteWidth + x / 2];
							int cmask = 0xf0 >> (((x + 1) % 2) * 4);
							int mask = 0xf0 >> ((j % 2) * 4);
							int nibble = (val & mask) >> (((j + 1) % 2) * 4);
							decompressedData[y * byteWidth + x / 2] =
								(byte) ((cval & cmask) | (nibble << (((x + 1) % 2) * 4)));
							x++;
						}
					}
				}
			}
			catch (ArrayIndexOutOfBoundsException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			rawDataSize = readOffset - offset;
		}
		else if (compression == BI_RLE8) {
			int x = 0;
			int y = 0;
			int byteWidth = w;
			decompressedDataSize = byteWidth * h;
			if (returnDecompressedData) {
				decompressedData = new byte[decompressedDataSize];
			}
			int readOffset = offset;
			try {
				while (true) {
					if (readOffset >= maxBufferOffset) {
						throw new MemoryAccessException(
							"Bitmap resource decompression exceeded memory constraint at " +
								buf.getAddress());
					}
					int val = buf.getByte(readOffset++);
					if (val == 0) { // escape
						val = buf.getByte(readOffset++);
						if (val == 1) {
							break; // End of Bitmap - break from loop
						}
						switch (val) {
							case 0: // EOL
								x = 0;
								y++;
								break;
							case 1: // End of Bitmap
								throw new AssertException(); // already handled
							case 2: // Delta
								int xdelta = buf.getByte(readOffset++) & 0xff;
								int ydelta = buf.getByte(readOffset++) & 0xff;
								x += xdelta;
								y += ydelta;
								break;
							default: // Absolute
								int numFollow = val & 0xff;
								if (decompressedData != null) {
									byte[] bytes = new byte[numFollow];
									buf.getBytes(bytes, readOffset);
									System.arraycopy(bytes, 0, decompressedData, y * byteWidth + x,
										bytes.length);
									x += numFollow;
								}
								readOffset += numFollow;
								readOffset += (readOffset % 2);
								break;
						}
						continue;
					}
					int run = val;
					val = buf.getByte(readOffset++);
					if (decompressedData != null) {
						for (int j = 0; j < run; j++) {
							if (x >= w || y >= h) {
								break;
							}
							decompressedData[y * byteWidth + x] = (byte) val;
							x++;
						}
					}
				}
			}
			catch (ArrayIndexOutOfBoundsException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}
			rawDataSize = readOffset - offset;
		}
		else {
			Msg.error(this, "Unsupported bitmap resource compression type " + compression + " at " +
				buf.getAddress());
		}
		return new BitmapDecompressResult(rawDataSize, decompressedDataSize, decompressedData);
	}

}
