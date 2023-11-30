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
import java.util.*;
import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.text.StringEscapeUtils;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.util.exception.CancelledException;

/**
 * Parse and manage object for the CaRT version 1 format, including managing the
 * header, footer, and decryptor objects as providing a combined view of the
 * optional header and footer metadata in a similar way to the original CaRT
 * python library.
 */
public class CartV1File {
	@SuppressWarnings("unused")
	private static short version = CartV1Constants.HEADER_VERSION;

	private String name = "<Unknown>";
	private String path = "<Unknown>";
	private long dataOffset = -1;
	private long payloadOriginalSize = -1;
	private long packedSize = -1;
	private Map<String, byte[]> footerHashes;
	private CartV1Header header;
	private CartV1Footer footer;
	private CartV1Decryptor decryptor;
	private long readerLength = -1;
	private BinaryReader internalReader;

	/**
	 * Constructs a new CartV1File read from the byte provider.
	 *
	 * @param byteProvider The byte provider from which to read
	 * @throws IOException                 If there was a problem reading from the
	 *                                     byte provider
	 * @throws CartInvalidCartException    If there was a formating error with the
	 *                                     CaRT file
	 * @throws CartInvalidARC4KeyException If the decryption of the payload or JSON
	 *                                     deserialization fails.
	 * @throws CartConfigurationException  If the configuration data for CaRT was
	 *                                     found, but invalid.
	 * @throws CancelledException          If the user cancels due to data error/warning
	 */
	public CartV1File(ByteProvider byteProvider) throws IOException, CartInvalidCartException,
			CartInvalidARC4KeyException, CartConfigurationException, CancelledException {
		this(new BinaryReader(byteProvider, true));
	}

	/**
	 * Constructs a new CartV1File read from the byte provider and user provided
	 * ARC4 key.
	 *
	 * @param byteProvider The byte provider from which to read
	 * @param arc4Key The ARC4 key to use as a user provided string
	 * @throws IOException                 If there was a problem reading from the
	 *                                     byte provider
	 * @throws CartInvalidCartException    If there was a formating error with the
	 *                                     CaRT file
	 * @throws CartInvalidARC4KeyException If the decryption of the payload or JSON
	 *                                     deserialization fails.
	 * @throws CartConfigurationException  If the configuration data for CaRT was
	 *                                     found, but invalid.
	 * @throws CancelledException          If the user cancels due to data error/warning
	 */
	public CartV1File(ByteProvider byteProvider, String arc4Key)
			throws IOException, CartInvalidCartException, CartInvalidARC4KeyException,
			CartConfigurationException, CancelledException {
		this(new BinaryReader(byteProvider, true), arc4Key);
	}

	/**
	 * Constructs a new CartV1File read from the little-endian binary reader.
	 *
	 * @param reader The little-endian binary reader from with to read
	 * @throws IOException                 If there was a problem reading from the
	 *                                     byte provider
	 * @throws CartInvalidCartException    If there was a formating error with the
	 *                                     CaRT file
	 * @throws CartInvalidARC4KeyException If the decryption of the payload or JSON
	 *                                     deserialization fails.
	 * @throws CartConfigurationException  If the configuration data for CaRT was
	 *                                     found, but invalid.
	 * @throws CancelledException          If the user cancels due to data error/warning
	 */
	public CartV1File(BinaryReader reader) throws IOException, CartInvalidCartException,
			CartInvalidARC4KeyException, CartConfigurationException, CancelledException {
		this(reader, null);
	}

	/**
	 * Constructs a new CartV1File read from the little-endian binary reader and
	 * provided key. If key is null, attempt to autodetect.
	 *
	 * @param reader The little-endian binary reader from with to read
	 * @param arc4Key The ARC4 key to use as a user provided string
	 * @throws IOException                 If there was a problem reading from the
	 *                                     byte provider
	 * @throws CartInvalidCartException    If there was a formating error with the
	 *                                     CaRT file
	 * @throws CartInvalidARC4KeyException If the decryption of the payload or JSON
	 *                                     deserialization fails.
	 * @throws CartConfigurationException  If the configuration data for CaRT was
	 *                                     found, but invalid.
	 * @throws CancelledException          If the user cancels due to data error/warning
	 */
	public CartV1File(BinaryReader reader, String arc4Key)
			throws IOException, CartInvalidCartException, CartInvalidARC4KeyException,
			CartConfigurationException, CancelledException {
		// Check that binary reader is Little-Endian
		if (!reader.isLittleEndian()) {
			throw new IOException("CaRT BinaryReader must be Little-Endian.");
		}

		readerLength = reader.length();

		// Check that there are at least enough bytes to contain a header and footer
		if (readerLength < CartV1Constants.MINIMUM_LENGTH) {
			throw new CartInvalidCartException("Data too small to be CaRT format.");
		}

		internalReader = reader.clone(0);

		// Load and validate header
		header = new CartV1Header(internalReader);

		// Load and validate footer
		footer = new CartV1Footer(internalReader);

		name = internalReader.getByteProvider().getName();
		dataOffset = header.dataStart();

		packedSize = footer.optionalFooterPosition() - dataOffset;
		if (packedSize <= 0 || packedSize > readerLength) {
			throw new CartInvalidCartException("Error calculating CaRT compressed payload size.");
		}

		if (arc4Key == null) {
			createDecryptor();
		}
		else {
			createDecryptor(arc4Key);
		}

		try {
			header.loadOptionalHeader(decryptor);
		}
		catch (CartInvalidARC4KeyException e) {
			throw new CartInvalidARC4KeyException("Decryption failed for header metadata: " + e);
		}

		try {
			footer.loadOptionalFooter(decryptor);
		}
		catch (CartInvalidARC4KeyException e) {
			throw new CartInvalidARC4KeyException("Decryption failed for footer metadata: " + e);
		}

		JsonObject optionalHeaderData = header.optionalHeaderData();

		// Get the payload name from the optional header data, if available;
		// if the CaRT file name ends with ".cart" drop the extension;
		// otherwise, add ".uncart"
		if (optionalHeaderData.has("name")) {
			path = optionalHeaderData.get("name").getAsString();
		}
		else {
			path = name;
			if (path.endsWith(".cart")) {
				path = path.substring(0, path.length() - 5);
			}
			else {
				path += ".uncart";
			}
		}

		JsonObject optionalFooterData = footer.optionalFooterData();

		// Load the length from the optional footer, if available. If the value
		// is less than 0 refuse to proceed. If the value is greater than 10 times
		// the compressed size warn the user that this seems odd.
		if (optionalFooterData.has("length")) {
			payloadOriginalSize = optionalFooterData.get("length").getAsLong();
			if (payloadOriginalSize < 0) {
				throw new CartInvalidCartException("Bad payload length in footer.");
			}
			else if (payloadOriginalSize > packedSize * 10) {
				if (!CartCancelDialogs.promptWarningContinue("Size Warning",
					"CaRT footer reports payload size <b>" +
						StringEscapeUtils.escapeHtml4(String.valueOf(payloadOriginalSize)) +
						"</b>, but this value seems unreasonable given the compressed size of <i>" +
						StringEscapeUtils.escapeHtml4((String.valueOf(packedSize))) +
						"</i>. Continue processing?")) {
					throw new CancelledException("Cancelled due to footer length field error.");
				}
			}
		}
		else {
			payloadOriginalSize = -1;
		}

		footerHashes = new LinkedHashMap<>();

		List<String> missingHashes = new ArrayList<>(); // List of hashes that are expected, but not
														// present

		// If an expected hash is in the optional footer load it. Refuse to continue if
		// it fails to parse correctly.
		for (String hashName : CartV1Constants.EXPECTED_HASHES.keySet()) {
			if (optionalFooterData.has(hashName)) {
				try {
					footerHashes.put(hashName,
						HexFormat.of().parseHex(optionalFooterData.get(hashName).getAsString()));
				}
				catch (IllegalArgumentException e) {
					throw new CartInvalidCartException("Bad " + hashName + " hash format.");
				}
			}
			else {
				missingHashes.add(hashName);
			}
		}

		if (footerHashes.isEmpty()) {
			if (!CartCancelDialogs.promptErrorContinue("No Hashes",
				"No hash data in CaRT footer metadata. Cannot verify content. Continue processing?")) {
				throw new CancelledException("Cancelled due to no hash data.");
			}
		}
		else if (!missingHashes.isEmpty()) {
			if (!CartCancelDialogs.promptErrorContinue("Missing Hashes",
				"Expected hash(es) missing: " + String.join(", ", missingHashes) +
					". Continue processing?")) {
				throw new CancelledException("Cancelled due to missing hash data (" +
					String.join(", ", missingHashes) + ").");
			}
		}
	}

	/**
	 * Create the CartV1Decryptor object including determining the appropriate key.
	 * First try the key in the header, if that fails check if a key is available in
	 * the default CaRT configuration INI file. After that try the default key and
	 * the private key placeholder. If all of those fail, raise an exception.
	 *
	 * @return The CartV1Decryptor object
	 * @throws IOException                 If there is a read failure of the data
	 * @throws CartInvalidCartException    If there was a formating error with the
	 *                                     CaRT file
	 * @throws CartInvalidARC4KeyException If no key could be determined
	 * @throws CartConfigurationException  If the configuration data for CaRT was
	 *                                     found, but invalid.
	 * @throws CancelledException          If the user cancels decryption
	 */
	private CartV1Decryptor createDecryptor() throws IOException, CartInvalidCartException,
			CartInvalidARC4KeyException, CartConfigurationException, CancelledException {
		if (header == null) {
			throw new CartInvalidCartException("CaRT header not initialized.");
		}
		// First, test the key from the header as-is, if it works return the decryptor
		// based on it.
		try {
			return createDecryptor(header.arc4Key());
		}
		catch (CartInvalidARC4KeyException e) {
			// ignore
		}

		List<byte[]> possibleKeys = new ArrayList<>();

		// Attempt to get a key from the default CaRT configuration INI file
		try {
			byte[] iniKey = getIniKey();

			if (iniKey != null) {
				possibleKeys.add(iniKey);
			}
		}
		catch (IOException e) {
			// ignore
		}

		// Try a couple default keys before reporting failure
		possibleKeys.add(CartV1Constants.DEFAULT_ARC4_KEY);
		possibleKeys.add(CartV1Constants.PRIVATE_ARC4_KEY_PLACEHOLDER);

		for (byte[] key : possibleKeys) {
			try {
				return createDecryptor(key);
			}
			catch (CartInvalidARC4KeyException e) {
				// ignore
			}
		}

		// If a valid key hasn't been determined, raise the appropriate exception
		throw new CartInvalidARC4KeyException("Private CaRT ARC4 key could not be determined.");
	}

	/**
	 * Create the CartV1Decryptor object using the specified key. Tested as-is, and as
	 * base64 decoded.
	 *
	 * @param proposedArc4Key The ARC4 key being proposed for this CaRT as a String
	 * @return The CartV1Decryptor object
	 * @throws IOException                 If there is a read failure of the data
	 * @throws CartInvalidCartException    If there was a formating error with the
	 *                                     CaRT file
	 * @throws CartInvalidARC4KeyException If no key could be determined
	 * @throws CartConfigurationException  If the configuration data for CaRT was
	 *                                     found, but invalid.
	 * @throws CancelledException          If the user cancels decryption
	 */
	private CartV1Decryptor createDecryptor(String proposedArc4Key)
			throws IOException, CartInvalidCartException, CartInvalidARC4KeyException,
			CartConfigurationException, CancelledException {

		// Pad/truncate to the proper length, then test as-is, if it works return the decryptor
		// based on it.
		try {
			byte[] arc4Key =
				Arrays.copyOf(proposedArc4Key.getBytes(), CartV1Constants.ARC4_KEY_LENGTH);
			return createDecryptor(arc4Key);
		}
		catch (CartInvalidARC4KeyException e) {
			// ignore
		}

		// *Very* basic base-64 checks before attempting
		if (proposedArc4Key.length() >= 4 && proposedArc4Key.length() <= 20 &&
			proposedArc4Key.length() % 4 == 0) {
			try {
				byte[] b64key = Base64.getDecoder().decode(proposedArc4Key);

				// If the proposed key is valid base64 encoding, pad/truncate it to the
				// proper length
				if (b64key.length != CartV1Constants.ARC4_KEY_LENGTH) {
					b64key = Arrays.copyOf(b64key, CartV1Constants.ARC4_KEY_LENGTH);
				}

				return createDecryptor(b64key);
			}
			catch (IllegalArgumentException | CartInvalidARC4KeyException e) {
				// ignore
			}
		}

		// If a valid key hasn't been determined, raise the appropriate exception
		throw new CartInvalidARC4KeyException("Private CaRT ARC4 key could not be determined.");
	}

	/**
	 * Create the CartV1Decryptor object using the specified key. Tested padded/truncated
	 * to the correct length.
	 *
	 * @param proposedArc4Key The ARC4 key being proposed for this CaRT
	 * @return The CartV1Decryptor object
	 * @throws IOException                 If there is a read failure of the data
	 * @throws CartInvalidCartException    If there was a formating error with the
	 *                                     CaRT file
	 * @throws CartInvalidARC4KeyException If no key could be determined
	 * @throws CartConfigurationException  If the configuration data for CaRT was
	 *                                     found, but invalid.
	 * @throws CancelledException          If the user cancels decryption
	 */
	private CartV1Decryptor createDecryptor(byte[] proposedArc4Key)
			throws IOException, CartInvalidCartException, CartInvalidARC4KeyException,
			CartConfigurationException, CancelledException {

		// Pad/truncate to the proper length if necessary
		if (proposedArc4Key.length != CartV1Constants.ARC4_KEY_LENGTH) {
			proposedArc4Key = Arrays.copyOf(proposedArc4Key, CartV1Constants.ARC4_KEY_LENGTH);
		}

		if (testKey(proposedArc4Key)) {
			decryptor = new CartV1Decryptor(proposedArc4Key);
			return decryptor;
		}

		// If a valid key hasn't been determined, raise the appropriate exception
		throw new CartInvalidARC4KeyException("Private CaRT ARC4 key could not be determined.");
	}

	/**
	 * Helper function to test a given key on the current CaRT data. Currently, this
	 * only uses the payload extractor test, but in the future should also test that
	 * the optional header and optional footer decrypt properly, if available.
	 *
	 * @param potentialARC4key The potential ARC4 key
	 * @return True if decryption was successful, false otherwise
	 * @throws IOException                 If there was a failure to read the data
	 * @throws CartInvalidCartException    If there was a formating error with the
	 *                                     CaRT file
	 * @throws CartInvalidARC4KeyException If there was another key error
	 * @throws CancelledException          If the user cancels decryption
	 */
	private boolean testKey(byte[] potentialARC4key) throws IOException, CartInvalidCartException,
			CartInvalidARC4KeyException, CancelledException {
		return CartV1PayloadExtractor.testExtraction(this.internalReader, this, potentialARC4key);
	}

	/**
	 * Attempt to get a decryption key from the standard CaRT configuration file
	 * (~/.cart/cart.cfg).
	 *
	 * @return The key from the configuration file, if found; otherwise, null.
	 * @throws IOException                If there was a failure to read data.
	 * @throws CartConfigurationException If the configuration data for CaRT was
	 *                                    found, but invalid.
	 */
	private byte[] getIniKey() throws IOException, CartConfigurationException {
		String configFileName = System.getProperty("user.home") + "/.cart/cart.cfg";
		byte[] validKey = null;

		try (BufferedReader configReader = new BufferedReader(new FileReader(configFileName))) {
			// Look for an ini format line of rc4_key = <base64>
			// account for variable whitespace and allow for a ;-delimited comment at the
			// end
			// Note: While this should probably be arc4_key, it must be rc4_key to match
			// CaRT module.
			Pattern pattern = Pattern.compile("^\\s*rc4_key\\s*=\\s*(([^\\s]{4}){1,5})\\s*(;.*)?$",
				Pattern.CASE_INSENSITIVE);
			String line;

			while ((line = configReader.readLine()) != null) {
				Matcher matcher = pattern.matcher(line);

				if (matcher.find()) {
					try {
						byte[] potentialARC4Key = Base64.getDecoder().decode(matcher.group(1));

						// Create a copy padded up to the key size; or truncated at the key size
						validKey = Arrays.copyOf(potentialARC4Key, CartV1Constants.ARC4_KEY_LENGTH);

						break;
					}
					catch (IllegalArgumentException e) {
						throw new CartConfigurationException(
							"rc4_key in " + configFileName + " is not valid base64-encoded data.");
					}
				}
			}
		}

		return validKey;
	}

	/**
	 * Get the name of the CaRT container file.
	 *
	 * @return The name of the CaRT container file.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Get the name of the CaRT payload file.
	 *
	 * @return The name of the CaRT payload file.
	 */
	public String getPath() {
		return path;
	}

	/**
	 * Get the offset to where the payload data in the CaRT file starts.
	 *
	 * @return The offset to the payload data.
	 */
	public long getDataOffset() {
		return dataOffset;
	}

	/**
	 * Get the original size of the original payload (without compression and
	 * encryption).
	 *
	 * @return The original size of the payload
	 */
	public long getDataSize() {
		return payloadOriginalSize;
	}

	/**
	 * Get the packed size of the payload (compressed and encrypted).
	 *
	 * @return The packed size of the payload
	 */
	public long getPackedSize() {
		return packedSize;
	}

	/**
	 * Get the value for the specified hash as stored in the footer or null if not
	 * available. This value will not be tested for validity until the payload is
	 * extracted.
	 * <p>
	 * <b>Note:</b> Only hash names specified in CartV1Constants.expectedHash (keys)
	 * are supported.
	 *
	 * @param hashName The name of the hash to be read
	 * @return The hash value bytes or null
	 */
	public byte[] getFooterHash(String hashName) {
		if (footerHashes.containsKey(hashName)) {
			return footerHashes.get(hashName);
		}

		return null;
	}

	/**
	 * Get the header object.
	 *
	 * @return The CartV1Header object.
	 */
	public CartV1Header getHeader() {
		return header;
	}

	/**
	 * Get the footer object.
	 *
	 * @return The CartV1Footer object.
	 */
	public CartV1Footer getFooter() {
		return footer;
	}

	/**
	 * Get the decryptor for the CaRT payload.
	 *
	 * @return The CartV1Decrypter object
	 */
	public CartV1Decryptor getDecryptor() {
		return decryptor;
	}

	/**
	 * Get the combined optional header and optional footer data as a single
	 * combined JSON object. This is similar to how the original python CaRT library
	 * works. Including, the fact that footer values will overwrite header values
	 * when keys collide. An empty JSON object will be returned if neither the
	 * optional header nor footer is available.
	 *
	 * @return The metadata JSON object.
	 */
	public JsonObject getMetadata() {
		JsonObject metadata = header.optionalHeaderData();

		// If we weren't able to get the optional header data, create a new empty JSON
		// object
		if (metadata == null) {
			metadata = new JsonObject();
		}

		JsonObject optionalFooterData = null;

		try {
			optionalFooterData = footer.optionalFooterData();
		}
		catch (CartInvalidCartException e) {
			// ignore
		}

		// If we were able to get the optional footer data then merge it's data with
		// whatever metadata is already available.
		if (optionalFooterData != null) {
			for (Entry<String, JsonElement> entry : optionalFooterData.entrySet()) {
				// This will overwrite any existing header values when the footer contains
				// a conflicting key. This is the same behavior as the python library.
				metadata.add(entry.getKey(), entry.getValue());
			}
		}

		return metadata;
	}

	/**
	 * Static function to quickly determine if the data in the byte provider appears
	 * to be CaRT version 1 format.
	 *
	 * @param byteProvider The byte provider from which to read
	 * @return True if CaRT version 1 data; otherwise, false.
	 */
	public static boolean isCart(ByteProvider byteProvider) {
		return isCart(new BinaryReader(byteProvider, true));
	}

	/**
	 * Static function to quickly determine if the data in the little-endian binary
	 * reader appears to be CaRT version 1 format.
	 *
	 * @param reader The little-endian binary reader from with to read
	 * @return True if CaRT version 1 data; otherwise, false.
	 */
	public static boolean isCart(BinaryReader reader) {
		return hasCartHeader(reader) && hasCartFooter(reader);
	}

	/**
	 * Static function to quickly determine if the data in the byte provider appears
	 * to have a CaRT version 1 format header.
	 *
	 * @param byteProvider The byte provider from which to read
	 * @return True if CaRT version 1 header; otherwise, false.
	 */
	public static boolean hasCartHeader(ByteProvider byteProvider) {
		return hasCartHeader(new BinaryReader(byteProvider, true));
	}

	/**
	 * Static function to quickly determine if the data in the little-endian binary
	 * reader appears to have a CaRT version 1 format header.
	 *
	 * @param reader The little-endian binary reader from with to read
	 * @return True if CaRT version 1 header; otherwise, false.
	 */
	public static boolean hasCartHeader(BinaryReader reader) {
		try {
			@SuppressWarnings("unused")
			CartV1Header header = new CartV1Header(reader);
			return true;
		}
		catch (IOException | CartInvalidCartException e) {
			// ignore
		}

		return false;
	}

	/**
	 * Static function to quickly determine if the data in the byte provider appears
	 * to have a CaRT version 1 format footer.
	 *
	 * @param byteProvider The byte provider from which to read
	 * @return True if CaRT version 1 footer; otherwise, false.
	 */
	public static boolean hasCartFooter(ByteProvider byteProvider) {
		return hasCartFooter(new BinaryReader(byteProvider, true));
	}

	/**
	 * Static function to quickly determine if the data in the little-endian binary
	 * reader appears to have a CaRT version 1 format footer.
	 *
	 * @param reader The little-endian binary reader from with to read
	 * @return True if CaRT version 1 footer; otherwise, false.
	 */
	public static boolean hasCartFooter(BinaryReader reader) {
		try {
			@SuppressWarnings("unused")
			CartV1Footer footer = new CartV1Footer(reader);
			return true;
		}
		catch (IOException | CartInvalidCartException e) {
			// ignore
		}

		return false;
	}
}
