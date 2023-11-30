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
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * StreamProcessor implementation to hash the data as it is being read and
 * provide a method to verify hashes upon completion.
 */
public class CartV1StreamHasher extends CartV1StreamProcessor {
	private Map<String, MessageDigest> hashers = new LinkedHashMap<>();
	private Map<String, byte[]> hashes = new LinkedHashMap<>();
	private Map<String, byte[]> finalHashes = new LinkedHashMap<>();

	/**
	 * Constructor for StreamHasher
	 *
	 * @param delegate InputStream to read and apply hashing
	 * @param cartFile The CaRT file from which it pull the expected hashes
	 * @throws NoSuchAlgorithmException If a hash is not supported by the underlying
	 *                                  MessageDigest implementation.
	 * @throws CartInvalidCartException If the CaRT format is bad
	 */
	public CartV1StreamHasher(InputStream delegate, CartV1File cartFile)
			throws NoSuchAlgorithmException, CartInvalidCartException {
		super(delegate);

		// List of hashes that are expected, but not present
		List<String> missingHashes = new ArrayList<>();

		// Iterate across the expected hashes, record which are missing and create hashers for
		// ones that are present
		for (Map.Entry<String, String> hashCheck : CartV1Constants.EXPECTED_HASHES.entrySet()) {
			byte[] footerHashValue = cartFile.getFooterHash(hashCheck.getKey());
			String hashName = hashCheck.getValue();

			// Check hash, if available
			if (footerHashValue != null) {
				hashes.put(hashCheck.getKey(), footerHashValue);
				hashers.put(hashCheck.getKey(), MessageDigest.getInstance(hashName));
			}
			else {
				missingHashes.add(hashCheck.getKey());
			}
		}

		if (!missingHashes.isEmpty()) {
			if (!CartCancelDialogs.promptErrorContinue("Missing Hashes",
				"Expected hash(es) missing: " + String.join(", ", missingHashes) +
					". Continue processing?")) {
				throw new CartInvalidCartException("Cancelled due to missing hash data (" +
					String.join(", ", missingHashes) + ").");
			}
		}
	}

	/**
	 * Read the next chunk in the stream and update all of the hashes
	 *
	 * @return True if more data is now available, False otherwise.
	 * @throws IOException If there is a read failure of the data
	 */
	@Override
	protected boolean readNextChunk() throws IOException {
		byte[] readBuffer = new byte[DEFAULT_BUFFER_SIZE];
		int bytesRead = -1;

		// Reset the current chunk and offset
		currentChunk = null;
		chunkPos = 0;

		if (hashers.isEmpty()) {
			return false;
		}

		bytesRead = delegate.read(readBuffer);

		if (bytesRead <= 0) {
			// No more data available, finalize the hashes
			for (Map.Entry<String, MessageDigest> hashCheck : hashers.entrySet()) {
				finalHashes.put(hashCheck.getKey(), hashCheck.getValue().digest());
			}

			// prevents trying to call digest() again
			hashers.clear();

			// Return false since no more data is available
			return false;
		}

		// Update all the hashes with the new data read
		for (MessageDigest hasher : hashers.values()) {
			hasher.update(readBuffer, 0, bytesRead);
		}

		currentChunk = Arrays.copyOf(readBuffer, bytesRead);

		return currentChunk != null && currentChunk.length > 0;
	}

	/**
	 * Check that hashes of the data read so far and match the values in the footer. Warn
	 * user if any hashes are missing. Throw an exception if any provided hash is
	 * bad.
	 *
	 * @return True if there are no bad hashed, and at least one hash was matched;
	 *         otherwise, false.
	 * @throws CartInvalidCartException If one or more hash is bad
	 */
	public boolean checkHashes() throws CartInvalidCartException {
		List<String> verifiedHashes = new ArrayList<>(); // List of hashes that are present and
														// correct
		List<String> badHashes = new ArrayList<>(); // List of hashes that are present, but wrong

		// Iterate across the hashers, check that the match. Record which are
		// bad or verified.
		for (Map.Entry<String, byte[]> hashCheck : finalHashes.entrySet()) {
			byte[] footerHashValue = hashes.get(hashCheck.getKey());

			try {
				if (Arrays.equals(hashCheck.getValue(), footerHashValue)) {
					verifiedHashes.add(hashCheck.getKey());
				}
				else {
					badHashes.add(hashCheck.getKey());
				}
			}
			catch (IllegalArgumentException e) {
				badHashes.add(hashCheck.getKey());
			}
		}

		if (!badHashes.isEmpty()) {
			throw new CartInvalidCartException("Hash(es) " + String.join(", ", badHashes) +
				" in footer doesn't match CaRT data contents.");
		}

		if (verifiedHashes.isEmpty()) {
			if (!CartCancelDialogs.promptErrorContinue("No Hashes",
				"No hash data in CaRT footer metadata. Cannot verify content. Continue processing?")) {
				throw new CartInvalidCartException("Cancelled due to no hash data.");
			}
		}

		// Return true if there are no bad hashed and at least one verified hash;
		// otherwise false
		return (badHashes.size() == 0) && (verifiedHashes.size() > 0);
	}
}
