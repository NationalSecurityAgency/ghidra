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
 * Class to manage reading and access to a CaRT version 1 file footer.
 */
public class CartV1Footer {
	// Mandatory footer values
	private String magic;
	private long reserved = -1;
	private long optionalFooterPosition = -1;
	private long optionalFooterLength = -1;

	// Optional footer data
	private JsonObject optionalFooterData;

	// Internal helper storage
	private long footerPosition = -1;
	private long readerLength = -1;
	private BinaryReader internalReader;

	/**
	 * Constructs a new CartV1Footer read from the byte provider.
	 *
	 * @param byteProvider The byte provider from which to read
	 * @throws IOException              If there was a problem reading from the byte
	 *                                  provider
	 * @throws CartInvalidCartException If there was a formating error with the CaRT
	 *                                  footer
	 */
	public CartV1Footer(ByteProvider byteProvider) throws IOException, CartInvalidCartException {
		this(new BinaryReader(byteProvider, true));
	}

	/**
	 * Constructs a new CartV1Footer, read from the little-endian binary reader.
	 *
	 * @param reader The little-endian binary reader from with to read
	 * @throws IOException              If there was a problem reading from the
	 *                                  binary reader
	 * @throws CartInvalidCartException If there was a formating error with the CaRT
	 *                                  footer
	 */
	public CartV1Footer(BinaryReader reader) throws IOException, CartInvalidCartException {
		// Check that binary reader is Little-Endian
		if (!reader.isLittleEndian()) {
			throw new IOException("CaRT BinaryReader must be Little-Endian.");
		}

		readerLength = reader.length();

		// Check that there are at least enough bytes to contain a footer
		if (readerLength < CartV1Constants.FOOTER_LENGTH) {
			throw new CartInvalidCartException("Data too small to contain CaRT footer.");
		}

		// Calculate and verify footer position
		footerPosition = readerLength - CartV1Constants.FOOTER_LENGTH;
		if (footerPosition < 0 || footerPosition > readerLength) {
			throw new CartInvalidCartException("Invalid CaRT footer position.");
		}

		// Clone the existing reader, but set position to the start of the mandatory
		// footer
		internalReader = reader.clone(footerPosition);

		// Read and verify footer magic value
		magic = internalReader.readNextAsciiString(CartV1Constants.FOOTER_MAGIC.length());
		if (!magic.equals(CartV1Constants.FOOTER_MAGIC)) {
			throw new CartInvalidCartException("Invalid CaRT footer magic value.");
		}

		// Read and verify footer reserved value
		reserved = internalReader.readNextLong();
		if (reserved != CartV1Constants.FOOTER_RESERVED) {
			throw new CartInvalidCartException("Invalid CaRT footer reserved value.");
		}

		// Read and verify optional footer position
		optionalFooterPosition = internalReader.readNextLong();
		if (optionalFooterPosition < 0 || optionalFooterPosition > footerPosition ||
			optionalFooterPosition > readerLength) {
			throw new CartInvalidCartException("Invalid CaRT optional footer position.");
		}

		// Read and verify optional footer length
		optionalFooterLength = internalReader.readNextLong();
		if (optionalFooterLength < 0 ||
			(optionalFooterPosition + optionalFooterLength) != footerPosition ||
			(optionalFooterPosition + optionalFooterLength) > readerLength) {
			throw new CartInvalidCartException("Invalid CaRT optional footer length.");
		}
	}

	/**
	 * Get the magic value read from the footer.
	 *
	 * @return The magic value read from the footer.
	 * @throws CartInvalidCartException If the footer object is not valid.
	 */
	protected String magic() throws CartInvalidCartException {
		return magic;
	}

	/**
	 * Get the position of the optional footer. Should be 0 if no optional footer is
	 * available.
	 *
	 * @return The position of the optional footer, 0 if no optional footer.
	 * @throws CartInvalidCartException If the footer object is not valid.
	 */
	protected long optionalFooterPosition() throws CartInvalidCartException {
		return optionalFooterPosition;
	}

	/**
	 * Get the length of the optional footer. Should be 0 if no optional footer is
	 * available.
	 *
	 * @return The length of the optional footer, 0 if no optional footer.
	 * @throws CartInvalidCartException If the footer object is not valid.
	 */
	protected long optionalFooterLength() throws CartInvalidCartException {
		return optionalFooterLength;
	}

	/**
	 * Get a copy of the optional footer data.
	 *
	 * @return A copy of the JsonObject optional footer data or null if unavailable.
	 * @throws CartInvalidCartException If the footer object is not valid.
	 */
	protected JsonObject optionalFooterData() throws CartInvalidCartException {
		JsonObject optionalFooterDataCopy;

		if (optionalFooterData != null) {
			optionalFooterDataCopy = optionalFooterData.deepCopy();
		}
		else {
			optionalFooterDataCopy = null;
		}

		return optionalFooterDataCopy;
	}

	/**
	 * Read and decrypt optional footer data and return a copy.
	 *
	 * @param decryptor An initialize decryptor with the correct ARC4 key
	 * @return JsonObject read and decrypted from the footer. Will be empty if no
	 *         optional footer is available.
	 * @throws CartInvalidCartException    If the footer object is not valid.
	 * @throws CartInvalidARC4KeyException If the decryption of JSON deserialization
	 *                                     fails.
	 * @throws IOException                 If there is a failure to read the footer data.
	 */
	public JsonObject loadOptionalFooter(CartV1Decryptor decryptor)
			throws CartInvalidCartException, CartInvalidARC4KeyException, IOException {
		byte[] encryptedOptionalFooter = null;

		if (optionalFooterLength > 0 &&
			(optionalFooterPosition + optionalFooterLength) == footerPosition &&
			(optionalFooterPosition + optionalFooterLength) < readerLength) {
			try {
				encryptedOptionalFooter = internalReader.readByteArray(optionalFooterPosition,
					(int) optionalFooterLength);
			}
			catch (IOException e) {
				// ignore
			}
		}

		if (encryptedOptionalFooter != null) {
			String decryptedOptionalFooter = decryptor.decryptToString(encryptedOptionalFooter);

			if (decryptedOptionalFooter == null) {
				throw new CartInvalidARC4KeyException("CaRT optional footer decryption failed.");
			}

			try {
				optionalFooterData =
					JsonParser.parseString(decryptedOptionalFooter).getAsJsonObject();
			}
			catch (IllegalStateException | JsonSyntaxException e) {
				throw new CartInvalidARC4KeyException(
					"CaRT decrypted optional footer not valid JSON.");
			}
		}

		// If there was no encrypted optional footer or parsing failed without an exception and
		// parseString returns `null` then set to empty JSON object
		if (optionalFooterData == null) {
			optionalFooterData = new JsonObject();
		}

		return optionalFooterData();
	}
}
