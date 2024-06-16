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

import java.io.IOException;

import com.google.gson.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

/**
 * Class to manage reading and access to a CaRT version 1 file header.
 */
public final class CartV1Header {
	// Mandatory header values
	private String magic;
	private short version = -1;
	private long reserved = -1;
	private byte[] arc4Key;
	private long optionalHeaderLength = -1;

	// Optional header data
	private JsonObject optionalHeaderData;

	// Internal helper storage
	private long readerLength = -1;
	private BinaryReader internalReader;

	/**
	 * Constructs a new CartV1Header read from the byte provider.
	 *
	 * @param byteProvider The byte provider from which to read
	 * @throws IOException              If there was a problem reading from the byte
	 *                                  provider
	 * @throws CartInvalidCartException If there was a formating error with the CaRT
	 *                                  header
	 */
	public CartV1Header(ByteProvider byteProvider) throws IOException, CartInvalidCartException {
		this(new BinaryReader(byteProvider, true));
	}

	/**
	 * Constructs a new CartV1Header, read from the little-endian binary reader.
	 *
	 * @param reader The little-endian binary reader from with to read
	 * @throws IOException              If there was a problem reading from the
	 *                                  binary reader
	 * @throws CartInvalidCartException If there was a formating error with the CaRT
	 *                                  header
	 */
	public CartV1Header(BinaryReader reader) throws IOException, CartInvalidCartException {
		// Check that binary reader is Little-Endian
		if (!reader.isLittleEndian()) {
			throw new IOException("CaRT BinaryReader must be Little-Endian.");
		}

		readerLength = reader.length();

		// Check that there are at least enough bytes to contain a header
		if (readerLength < CartV1Constants.HEADER_LENGTH) {
			throw new CartInvalidCartException("Data too small to contain CaRT header.");
		}

		// Clone the existing reader, but set position to the start of the header
		// (beginning of file, offset 0)
		internalReader = reader.clone(0);

		// Read and verify header magic value
		magic = internalReader.readNextAsciiString(CartV1Constants.HEADER_MAGIC.length());
		if (!magic.equals(CartV1Constants.HEADER_MAGIC)) {
			throw new CartInvalidCartException("Invalid CaRT header magic value.");
		}

		// Read and verify CaRT version number
		version = internalReader.readNextShort();
		if (version != CartV1Constants.HEADER_VERSION) {
			throw new CartInvalidCartException("Invalid CaRT header version number.");
		}

		// Read and verify header reserved value
		reserved = internalReader.readNextLong();
		if (reserved != CartV1Constants.HEADER_RESERVED) {
			throw new CartInvalidCartException("Invalid CaRT header reserved value.");
		}

		// Read ARC4 key, this may be an arbitrary value -- no verification until
		// decryption is attempted
		arc4Key = internalReader.readNextByteArray(CartV1Constants.ARC4_KEY_LENGTH);

		// Read and verify optional header length
		optionalHeaderLength = internalReader.readNextLong();
		if (optionalHeaderLength < 0 || optionalHeaderLength > (readerLength -
			CartV1Constants.HEADER_LENGTH - CartV1Constants.FOOTER_LENGTH)) {
			throw new CartInvalidCartException("Invalid CaRT optional header length.");
		}
	}

	/**
	 * Get the magic value read from the header.
	 *
	 * @return The magic value read from the header.
	 */
	protected String magic() {
		return magic;
	}

	/**
	 * Get the version of the CaRT file.
	 *
	 * @return The version of the CaRT file.
	 */
	protected short version() {
		return version;
	}

	/**
	 * Get a copy of the ARC4 key read from the header.
	 *
	 * @return A copy of the ARC4 key read from the header.
	 * @throws CartInvalidCartException If the header object is not valid.
	 */
	protected byte[] arc4Key() throws CartInvalidCartException {
		byte[] arc4KeyCopy = new byte[CartV1Constants.ARC4_KEY_LENGTH];

		if (this.arc4Key != null) {
			System.arraycopy(this.arc4Key, 0, arc4KeyCopy, 0, CartV1Constants.ARC4_KEY_LENGTH);
		}
		else {
			throw new CartInvalidCartException("No ARC4 key available for CaRT.");
		}

		return arc4KeyCopy;
	}

	/**
	 * Get the location where data starts within the CaRT file, accounting for the
	 * header and any optional header data.
	 *
	 * @return The starting offset to the payload data.
	 */
	protected long dataStart() {
		return CartV1Constants.HEADER_LENGTH + optionalHeaderLength;
	}

	/**
	 * Get the length of the optional header. Should be 0 if no optional header is
	 * available.
	 *
	 * @return The length of the optional header, 0 if no optional header.
	 */
	protected long optionalHeaderLength() {
		return optionalHeaderLength;
	}

	/**
	 * Get a copy of the optional header data.
	 *
	 * @return A copy of the JsonObject optional header data or null if unavailable.
	 */
	protected JsonObject optionalHeaderData() {
		JsonObject optionalHeaderDataCopy;

		if (optionalHeaderData != null) {
			optionalHeaderDataCopy = optionalHeaderData.deepCopy();
		}
		else {
			optionalHeaderDataCopy = null;
		}

		return optionalHeaderDataCopy;
	}

	/**
	 * Read and decrypt optional header data and return a copy.
	 *
	 * @param decryptor An initialize decryptor with the correct ARC4 key
	 * @return JsonObject read and decrypted from the header. Will be empty if no
	 *         optional header is available.
	 * @throws CartInvalidARC4KeyException If the decryption of JSON deserialization
	 *                                     fails.
	 * @throws IOException                 If there is a failure to read the header data.
	 */
	public JsonObject loadOptionalHeader(CartV1Decryptor decryptor)
			throws CartInvalidARC4KeyException, IOException {
		byte[] encryptedOptionalHeader = null;

		if (optionalHeaderLength > 0 && optionalHeaderLength <= (readerLength -
			CartV1Constants.HEADER_LENGTH - CartV1Constants.FOOTER_LENGTH)) {
			try {
				encryptedOptionalHeader = internalReader
						.readByteArray(CartV1Constants.HEADER_LENGTH, (int) optionalHeaderLength);
			}
			catch (IOException e) {
				// ignore
			}
		}

		if (encryptedOptionalHeader == null) {
			/**
			 * Initialize the optionalHeaderData as an empty JSON object when the optional
			 * header length or position is invalid, when the length is 0 which indicates
			 * that there is no optional header, or when reading the data failed.
			 */
			optionalHeaderData = new JsonObject();
		}
		else {

			String decryptedOptionalHeader = decryptor.decryptToString(encryptedOptionalHeader);

			if (decryptedOptionalHeader != null) {
				try {
					optionalHeaderData =
						JsonParser.parseString(decryptedOptionalHeader).getAsJsonObject();
				}
				catch (IllegalStateException | JsonSyntaxException e) {
					throw new CartInvalidARC4KeyException(
						"CaRT decrypted optional header not valid JSON.");
				}

				// If parsing failed without an exception and parseString returns `null`,
				// set to empty JSON object
				if (optionalHeaderData == null) {
					optionalHeaderData = new JsonObject();
				}
			}
			else {
				throw new CartInvalidARC4KeyException("CaRT optional header decryption failed.");
			}
		}

		return optionalHeaderData();
	}
}
