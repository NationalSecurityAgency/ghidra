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
package ghidra.file.formats.cart;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Class to implement the payload extractor to decrypt and decompress the
 * payload contents. Provides output stream content of decrypted and decompressed file data.
 */
public class CartV1PayloadExtractor {
	/**
	 * Internal little-endian {@link BinaryReader} object for access to original file bytes.
	 */
	private BinaryReader reader;

	/**
	 * Internal {@link OutputStream} that will received the payload bytes.
	 */
	private OutputStream tempFos;

	/**
	 * {@link CartV1File} object from which to pull all relevant metadata for payload extraction.
	 */
	private CartV1File cartFile;

	/**
	 * Create the payload extractor for the specified byte provider that will output
	 * to the specified output stream.
	 *
	 * @param byteProvider The byte provider from which to read
	 * @param os           The output stream to write to
	 * @param cartFile     The CaRT file being read
	 * @throws IOException If there is a failure to read the data.
	 */
	public CartV1PayloadExtractor(ByteProvider byteProvider, OutputStream os, CartV1File cartFile)
			throws IOException {
		this(new BinaryReader(byteProvider, true), os, cartFile);
	}

	/**
	 * Create the payload extractor for the specified little-endian binary reader
	 * that will output to the specified output stream.
	 *
	 * @param reader   The little-endian binary reader from with to read
	 * @param os       The output stream to write to
	 * @param cartFile The CaRT file being read
	 * @throws IOException If there is a failure to read the data.
	 */
	public CartV1PayloadExtractor(BinaryReader reader, OutputStream os, CartV1File cartFile)
			throws IOException {
		// Check that binary reader is Little-Endian
		if (!reader.isLittleEndian()) {
			throw new IOException("CaRT BinaryReader must be Little-Endian.");
		}
		this.reader = reader;
		this.tempFos = os;
		this.cartFile = cartFile;
	}

	/**
	 * Callback to perform actual extraction of CaRT payload data to the output
	 * stream.
	 *
	 * @param monitor Monitor for status messages and cancellation
	 * @throws CancelledException If the extraction is cancelled
	 * @throws IOException        If an error occurs with the data, CaRT format, or
	 *                            hashes.
	 */
	public void extract(TaskMonitor monitor) throws CancelledException, IOException {

		monitor.setMessage("Reading CaRT data");

		ByteProviderWrapper subProvider = new ByteProviderWrapper(reader.getByteProvider(),
			cartFile.getDataOffset(), cartFile.getPackedSize());
		InputStream is = subProvider.getInputStream(0);
		CartV1StreamHasher hashedInputStream = null;
		try {
			is = new CartV1StreamDecryptor(is, cartFile.getDecryptor().getARC4Key());
			is = new CartV1StreamDecompressor(is);

			hashedInputStream = new CartV1StreamHasher(is, cartFile);
		}
		catch (NoSuchAlgorithmException | CartInvalidCartException e) {
			throw new IOException(e);
		}

		FSUtilities.streamCopy(hashedInputStream, tempFos, monitor);

		monitor.setMessage("Checking hashes...");
		try {
			hashedInputStream.checkHashes();
		}
		catch (CartInvalidCartException e) {
			throw new IOException("Invalid CaRT ARC4 hashes: " + e.getMessage());
		}
	}

	/**
	 * Test that the first two bytes of the CaRT payload data decrypts to a valid
	 * ZLIB prefix.
	 *
	 * @param reader   The little-endian binary reader from with to read
	 * @param cartFile The CaRT file being read
	 * @param arc4Key  The ARC4 key being tested.
	 * @return True if decryption of the first 64 bytes succeeds and the first two
	 *         bytes match zlib header bytes.
	 * @throws IOException                 If there is a failure to read the data.
	 * @throws CartInvalidCartException    If there is a format error to the data
	 * @throws CartInvalidARC4KeyException If the decryption fails.
	 * @throws CancelledException          If the user cancels the UI. For this function the UI
	 *                                     isn't shown so this isn't expected to happen.
	 */
	public static boolean testExtraction(BinaryReader reader, CartV1File cartFile, byte[] arc4Key)
			throws IOException, CartInvalidCartException, CartInvalidARC4KeyException,
			CancelledException {
		if (cartFile.getDataOffset() <= 0) {
			throw new CartInvalidCartException("Bad CaRT payload data offset");
		}

		int length = (int) (cartFile.getPackedSize());

		// limit the length being used to just the first 64 bytes
		if (length > 64) {
			length = 64;
		}

		byte[] encryptedAndCompressedData = reader.readByteArray(cartFile.getDataOffset(), length);

		byte[] compressedData = CartV1Decryptor.decrypt(arc4Key, encryptedAndCompressedData);

		if (compressedData != null) {
			// Trim down to the first two bytes for comparison
			compressedData = Arrays.copyOfRange(compressedData, 0, 2);

			for (byte[] zlibBytes : CartV1Constants.ZLIB_HEADER_BYTES) {
				// On the first match, return true
				if (Arrays.equals(compressedData, zlibBytes)) {
					return true;
				}
			}
		}

		// If data didn't decompress or we didn't find matching header bytes then return
		// false
		return false;
	}
}
