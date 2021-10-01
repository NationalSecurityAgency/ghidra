/* ###
 * IP: Public Domain
 * NOTE: https://github.com/soffes/pngdefry
 */
package ghidra.file.formats.ios.png;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.zip.*;

import ghidra.file.formats.zlib.ZLIB;

public class CrushedPNGUtil {

	/**
	 * Returns the converted bytes of the CrushedPNG to now represent
	 * the structure and formatting of a normal non-crushed PNG.
	 * @param png the CrushedPNG object
	 * @return An InputStream of the correctly formated bytes of a png
	 * @throws Exception 
	 */
	public static byte[] getUncrushedPNGBytes(ProcessedPNG png) throws Exception {
		boolean foundIHDR = false;
		boolean foundIDAT = false;
		boolean foundCgBI = false;
		IHDRChunk ihdrChunk = null;
		byte[] repackArray = null;
		List<PNGChunk> wantedChunks = new ArrayList<>();
		ByteArrayOutputStream idatStream = new ByteArrayOutputStream();

		for (PNGChunk chunk : png.getChunkArray()) {
			byte[] idBytes = chunk.getChunkIDBytes();

			//Ignore the inserted CgBI chunk
			if (!(Arrays.equals(idBytes, CrushedPNGConstants.INSERTED_IOS_CHUNK))) {
				if (Arrays.equals(idBytes, CrushedPNGConstants.IHDR_CHUNK)) {
					//Msg.debug(this, "Found IHDR Chunk");

					foundIHDR = true;
					ihdrChunk = new IHDRChunk(chunk);
					wantedChunks.add(chunk);
					byte[] checksum = calculateCRC32(chunk);
					if (!Arrays.equals(checksum, chunk.getCrc32Bytes())) {
						throw new PNGFormatException("Bad CRC32 on " + chunk.getChunkID() +
							" chunk");
					}

				}

				//All Other chunks. Look for the IDAT Chunks to fix RGB(A) values
				else if (Arrays.equals(idBytes, CrushedPNGConstants.IDAT_CHUNK)) {
					//Msg.debug(this, "Found IDAT Chunk");

					idatStream.write(chunk.getData());
					wantedChunks.add(chunk);
					foundIDAT = true;
					byte[] checksum = calculateCRC32(chunk);
					if (!Arrays.equals(checksum, chunk.getCrc32Bytes())) {
						throw new PNGFormatException("Bad CRC32 on " + chunk.getChunkID() +
							" chunk");
					}

				}
				else {
					//Msg.debug(this, "Found " + chunk.getIDString() + " Chunk");

					wantedChunks.add(chunk);
					byte[] checksum = calculateCRC32(chunk);
					if (!Arrays.equals(checksum, chunk.getCrc32Bytes())) {
						throw new PNGFormatException("Bad CRC32 on " + chunk.getChunkID() +
							" chunk");
					}

				}
			}
			else {
				foundCgBI = true;
			}
		}

		if (!foundIHDR) {
			throw new PNGFormatException("Missing IHDR Chunk");
		}
		if (!foundIDAT) {
			throw new PNGFormatException("Missing IDAT chunk(s)");
		}
		if (!foundCgBI) {
			throw new PNGFormatException("Missing CgBI chunk. PNG is not in crushed format");
		}
		if (ihdrChunk == null) {
			throw new PNGFormatException("Invalid IHDRChunk found to be null");
		}

		//Process the IDAT chunks
		if (ihdrChunk.getBitDepth() == 8 && ihdrChunk.getColorType() == 2 ||
			ihdrChunk.getColorType() == 6) {

			int expectedSize =
				(ihdrChunk.getBytesPerLine() * ihdrChunk.getImgHeight()) +
					ihdrChunk.getRowFilterBytes();
			byte[] results;
			try (ByteArrayOutputStream decompressedOutput = new ByteArrayOutputStream(expectedSize);
				InflaterOutputStream inflaterStream = new InflaterOutputStream(decompressedOutput)) {

				inflaterStream.write(ZLIB.ZLIB_COMPRESSION_DEFAULT);
				idatStream.writeTo(inflaterStream);
				inflaterStream.finish();
				results = decompressedOutput.toByteArray();
			}
			if (results.length != expectedSize) {
				throw new PNGFormatException("Decompression Error, expected " + expectedSize +
					" bytes, but got " + results.length + " bytes");
			}

			//Processes the IDAT chunks to 'uncrushify' them
			processIDATChunks(ihdrChunk, results);

			try (ByteArrayOutputStream compressedOutput = new ByteArrayOutputStream(CrushedPNGConstants.INITIAL_REPACK_SIZE);
				DeflaterOutputStream deflaterStream = new DeflaterOutputStream(compressedOutput)) {

				deflaterStream.write(results);
				deflaterStream.finish();
				deflaterStream.flush();
				repackArray = compressedOutput.toByteArray();
			}
		}

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(CrushedPNGConstants.SIGNATURE_BYTES);

		//Rebuild the new PNG useing the origional chunks and replacing the old crushed IDAT chunks
		boolean wroteIDAT = false;
		for (PNGChunk chunk : png.getChunkArray()) {
			byte[] idBytes = chunk.getChunkIDBytes();
			if (!(Arrays.equals(idBytes, CrushedPNGConstants.INSERTED_IOS_CHUNK))) {

				//If the chunk is the old IDAT chunk replace with new IDAT data
				if ((repackArray != null) && Arrays.equals(idBytes, CrushedPNGConstants.IDAT_CHUNK)) {
					if (!wroteIDAT) {
						//Write the chunk data length
						int dataLength = repackArray.length;
						byte[] lengthBytes = ByteBuffer.allocate(4).putInt(dataLength).array();
						outputStream.write(lengthBytes);

						//Gather ID and data together to calculate CRC32
						byte[] idat = new byte[CrushedPNGConstants.IDAT_CHUNK.length + dataLength];
						for (int i = 0; i < CrushedPNGConstants.IDAT_CHUNK.length; i++) {
							idat[i] = CrushedPNGConstants.IDAT_CHUNK[i];
						}
						for (int i = 0; i < dataLength; i++) {
							idat[CrushedPNGConstants.IDAT_CHUNK.length + i] = repackArray[i];
						}

						//Write the chunk data
						outputStream.write(idat);

						//Calculate and write chunk crc32
						byte[] checksum = calculateCRC32(idat);
						outputStream.write(checksum);

						wroteIDAT = true;
					}
				}
				else {

					//For any other wanted chunks other than IDAT insert them back in
					//Write the chunk data length
					outputStream.write(chunk.getLengthBytes());

					//Write the chunk ID
					outputStream.write(idBytes);

					//Write the chunk data
					outputStream.write(chunk.getData());

					//Calculate and write CRC32
					//outputStream.write(chunk.getCrc32());
					byte[] checksum = calculateCRC32(chunk);
					outputStream.write(checksum);
				}
			}

		}

		return outputStream.toByteArray();
	}

	/**
	 * Does the processing to uncrushify the PNG IDAT chunks
	 * @param ihdrChunk the IHDR chunk to pull meta deta from
	 * @param decompressedResult result of the zlib decompression
	 * @throws PNGFormatException
	 */
	private static void processIDATChunks(IHDRChunk ihdrChunk, byte[] decompressedResult)
			throws PNGFormatException {
		int width;
		int height;
		if (ihdrChunk.getInterlaceMethod() == CrushedPNGConstants.ADAM7_INTERLACE) {
			//Msg.debug(this, "Checking Adam7 unpacking");
			int y = 0;
			for (int pass = 0; pass < CrushedPNGConstants.STARTING_COL.length; pass++) {
				width =
					(ihdrChunk.getImgWidth() - CrushedPNGConstants.STARTING_COL[pass] +
						CrushedPNGConstants.COL_INCREMENT[pass] - 1) /
						CrushedPNGConstants.COL_INCREMENT[pass];
				height =
					(ihdrChunk.getImgHeight() - CrushedPNGConstants.STARTING_ROW[pass] +
						CrushedPNGConstants.ROW_INCREMENT[pass] - 1) /
						CrushedPNGConstants.ROW_INCREMENT[pass];

				int row = 0;
				while (row < height) {
					if (decompressedResult[y] > 4) {
						throw new PNGFormatException("Unknown row filter type " +
							decompressedResult[y]);
					}

					//Skip row filter byte
					y++;

					//skip rest of row
					y += width * ihdrChunk.getBytesPerPalette();
					row++;
				}
			}

			y = 0;
			for (int pass = 0; pass < CrushedPNGConstants.STARTING_COL.length; pass++) {

				//Formula taken from pngcheck
				width =
					(ihdrChunk.getImgWidth() - CrushedPNGConstants.STARTING_COL[pass] +
						CrushedPNGConstants.COL_INCREMENT[pass] - 1) /
						CrushedPNGConstants.COL_INCREMENT[pass];
				height =
					(ihdrChunk.getImgHeight() - CrushedPNGConstants.STARTING_ROW[pass] +
						CrushedPNGConstants.ROW_INCREMENT[pass] - 1) /
						CrushedPNGConstants.ROW_INCREMENT[pass];

				int startAt = y;
				int row = 0;
				while (row < height) {

					//skip row filter byte
					y++;

					//Swap all bytes in this row
					int x = 0;
					while (x < width) {
						byte tmpByte = decompressedResult[y + 2];
						decompressedResult[y + 2] = decompressedResult[y];
						decompressedResult[y] = tmpByte;
						y += ihdrChunk.getBytesPerPalette();
						x++;
					}
					row++;
				}

				//RGBA
				if (ihdrChunk.getColorType() == 6) {
					removeRowFilters(width, height, decompressedResult, startAt);
					demultiplyAlpha(width, height, decompressedResult, startAt);
					applyRowFilters(width, height, decompressedResult, startAt);
				}
			}
		}
		else {

			//check row filters
			int y = 0;
			while (y < (ihdrChunk.getBytesPerLine() * ihdrChunk.getImgHeight() + ihdrChunk.getRowFilterBytes())) {
				if (decompressedResult[y] > 4) {
					throw new PNGFormatException("Unkown row filter type " + decompressedResult[y]);
				}

				//skip row filter byte
				y++;

				//skip entire row
				y += ihdrChunk.getBytesPerLine();
			}
			y = 0;
			while (y < (ihdrChunk.getBytesPerLine() * ihdrChunk.getImgHeight() + ihdrChunk.getRowFilterBytes())) {

				//skip row filter byte
				y++;

				//swap all bytes in this row
				int x = 0;
				while (x < ihdrChunk.getImgWidth()) {
					byte tmpByte = decompressedResult[y + 2];
					decompressedResult[y + 2] = decompressedResult[y];
					decompressedResult[y] = tmpByte;
					y += ihdrChunk.getBytesPerPalette();
					x++;
				}
			}
			if (ihdrChunk.getColorType() == 6) { //RGBA
				removeRowFilters(ihdrChunk.getImgWidth(), ihdrChunk.getImgHeight(),
					decompressedResult, 0);
				demultiplyAlpha(ihdrChunk.getImgWidth(), ihdrChunk.getImgHeight(),
					decompressedResult, 0);
				applyRowFilters(ihdrChunk.getImgWidth(), ihdrChunk.getImgHeight(),
					decompressedResult, 0);
			}
		}

	}

	/**
	 * Removes the row filters from the image data
	 * @param width the image width
	 * @param height the image height
	 * @param data the image data
	 * @param offset the offset into data
	 */
	private static void removeRowFilters(int width, int height, byte[] data, int offset) {

		/*
		 * Yes, it is generally bad convention to have x in function scope in this way. However the 
		 * source code this was retrieved from www.jongware.com/pngdefry.html
		 * has cases where x could be 4*width or 0 such as case 3 in the switch below
		 * so I am duplicating the original implementation as closely as possible.
		 */
		int x = 0;
		int srcPtr = offset;

		for (int y = 0; y < height; y++) {
			int rowFilter = data[srcPtr];
			srcPtr++;

			switch (rowFilter) {
				case 0: //None
					break;

				case 1: //Sub
					for (x = 4; x < 4 * width; x++) {
						data[srcPtr + x] += data[srcPtr + (x - 4)];
					}
					break;

				case 2: //Up
					int upPtr = srcPtr - 4 * width - 1;
					if (y > 0) {
						for (x = 4; x < 4 * width; x++) {
							data[srcPtr + x] += data[upPtr + x];
						}
					}
					break;

				case 3: //Average
					upPtr = srcPtr - 4 * width - 1;

					if (y == 0) {
						for (x = 4; x < 4 * width; x++) {
							data[srcPtr + x] += ((data[upPtr + x] + data[srcPtr + (x - 4)]) >> 1);
						}
					}
					else {
						data[srcPtr] += (data[upPtr + x] >> 1);
						for (x = 4; x < 4 * width; x++) {
							data[srcPtr + x] += ((data[upPtr + x] + data[srcPtr + (x - 4)]) >> 1);
						}
					}
					break;

				case 4: //Paeth
					upPtr = srcPtr - 4 * width - 1;

					for (x = 0; x < 4 * width; x++) {
						int leftPix = 0;
						int topPix = 0;
						int topLeftPix = 0;
						if (x > 0) {
							leftPix = data[srcPtr + (x - 4)];
						}
						if (y > 0) {
							topPix = data[upPtr + x];
							if (x >= 4) {
								topLeftPix = data[upPtr + (x - 4)];
							}
						}
						int p = leftPix + topPix - topLeftPix;
						int pa = p - leftPix;
						if (pa < 0) {
							pa = -pa;
						}
						int pb = p - topPix;
						if (pb < 0) {
							pb = -pb;
						}
						int pc = p - topLeftPix;
						if (pc < 0) {
							pc = -pc;
						}

						int value;
						if (pa <= pb && pa <= pc) {
							value = leftPix;
						}
						else if (pb < pc) {
							value = topPix;
						}
						else {
							value = topLeftPix;
						}
						data[srcPtr + x] += value;
					}
					break;

			}
			srcPtr += 4 * width;
		}

	}

	/**
	 * Applies the row filters onto the png data based on source code from
	 * http://www.jongware.com/pngdefry.html
	 * @param width the image width
	 * @param height the image height
	 * @param data the image data
	 * @param offset the offset into the data
	 */
	private static void applyRowFilters(int width, int height, byte[] data, int offset) {

		/*
		 * Yes, it is generally bad convention to have x in function scope in this way. However the 
		 * source code this was retrieved from www.jongware.com/pngdefry.html
		 * has cases where x could be 4*width or 0 such as case 3 in the switch below
		 * so I am duplicating the original implementation as closely as possible.
		 */
		int x = 0;
		int srcPtr = offset;

		for (int y = 0; y < height; y++) {
			int rowFilter = data[srcPtr];
			srcPtr++;
			switch (rowFilter) {
				case 0: //None
					break;

				case 1: //Sub
					for (x = 4 * width - 1; x >= 4; x--) {
						data[srcPtr + x] -= data[srcPtr + (x - 4)];
					}
					break;

				case 2: //Up
					if (y > 0) {
						int upPtr = srcPtr - 1;
						for (x = 4 * width - 1; x >= 0; x--) {
							data[srcPtr + x] -= data[upPtr + x];
						}
					}
					break;

				case 3: //Average
					int upPtr = srcPtr - 4 * width - 1;
					if (y == 0) {
						for (x = 4 * width - 1; x >= 4; x--) {
							data[srcPtr + x] -= (data[srcPtr + (x - 4) >> 1]);
						}
					}
					else {
						data[srcPtr] -= (data[upPtr + x] >> 1);
						for (x = 4 * width - 1; x >= 4; x--) {
							data[srcPtr + x] -= ((data[upPtr + x] + data[srcPtr + (x - 4)]) >> 1);
						}
					}
					break;

				case 4: //Paeth
					upPtr = srcPtr - 1;
					for (x = 4 * width - 1; x >= 0; x--) {
						int leftPix = 0;
						int topPix = 0;
						int topLeftPix = 0;
						if (x > 0) {
							leftPix = data[srcPtr + (x - 4)];
						}
						if (y > 0) {
							topPix = data[upPtr + x];
							if (x >= 4) {
								topLeftPix = data[upPtr + (x - 4)];
							}
						}
						int p = leftPix + topPix - topLeftPix;
						int pa = p - leftPix;
						if (pa < 0) {
							pa = -pa;
						}
						int pb = p - topPix;
						if (pb < 0) {
							pb = -pb;
						}
						int pc = p - topLeftPix;
						if (pc < 0) {
							pc = -pc;
						}
						int value;
						if (pa <= pb && pa <= pc) {
							value = topPix;
						}
						else {
							value = topLeftPix;
						}
						data[srcPtr + x] -= value;
					}
					break;

			}
			srcPtr += 4 * width;
		}
	}

	/**
	 * Demultiplies the Alpha based on source code from http://www.jongware.com/pngdefry.html
	 * @param width image width
	 * @param height image height
	 * @param data image data
	 * @param offset offset into data
	 */
	private static void demultiplyAlpha(int width, int height, byte[] data, int offset) {
		int srcPtr = offset;

		for (int i = 0; i < height; i++) {

			//skip rowFilter
			srcPtr++;
			for (int x = 0; x < 4 * width; x += 4) {
				if (data[srcPtr + (x + 3)] > 0) {
					data[srcPtr + x] =
						(byte) ((data[srcPtr + x] * 255 + (data[srcPtr + (x + 3)] >> 1)) / data[srcPtr +
							(x + 3)]);

					data[srcPtr + (x + 1)] =
						(byte) ((data[srcPtr + (x + 1)] * 255 + (data[srcPtr + (x + 3)] >> 1)) / data[srcPtr +
							(x + 3)]);

					data[srcPtr + (x + 2)] =
						(byte) ((data[srcPtr + (x + 2)] * 255 + (data[srcPtr + (x + 3)] >> 1)) / data[srcPtr +
							(x + 3)]);
				}
			}
			srcPtr += 4 * width;
		}

	}

	/**
	 * Prepends the needed Zlib header to the set of idatChunks 
	 * in order to inflate the bytes
	 * @param idatChunks the set of idat chunks
	 * @return idat chunks with the new header
	 */
	private static byte[] getFixedIdatDataBytes(ByteArrayOutputStream idatChunks) {

		//Prepend the needed Zlib header info to the IDAT chunk data
		byte[] idatData = idatChunks.toByteArray();
		byte[] fixedIdatData = new byte[idatData.length + 2];
		fixedIdatData[0] = ZLIB.ZLIB_COMPRESSION_DEFAULT[0];
		fixedIdatData[1] = ZLIB.ZLIB_COMPRESSION_DEFAULT[1];
		for (int i = 0; i < idatData.length; i++) {
			fixedIdatData[i + 2] = idatData[i];
		}
		return fixedIdatData;
	}

	/**
	 * Calculates the crc32 based on a byte[]
	 * @param data the byte array to calculate crc32 from
	 * @return The crc32 result
	 */
	private static byte[] calculateCRC32(byte[] data) {
		CRC32 checksum = new CRC32();
		checksum.update(data);
		long result = checksum.getValue();
		return ByteBuffer.allocate(4).putInt((int) result).array();
	}

	/**
	 * Calculates the crc32 based on info gathered from a given PNGChunk
	 * @param chunk the chunk to calculate crc32 from
	 * @return The crc32 result
	 */
	private static byte[] calculateCRC32(PNGChunk chunk) {
		CRC32 checksum = new CRC32();
		checksum.update(ByteBuffer.allocate(4 + chunk.getLength()).putInt(chunk.getChunkID()).put(
			chunk.getData()).array());
		long result = checksum.getValue();
		return ByteBuffer.allocate(4).putInt((int) result).array();

	}
}
