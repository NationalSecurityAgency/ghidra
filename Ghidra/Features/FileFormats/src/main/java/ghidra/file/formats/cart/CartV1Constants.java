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

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.util.HashUtilities;

/**
 * Helper class from providing all the constants required for parsing a CaRT
 * format (Version 1) file.
 * <p>
 * From CaRT Source, cart.py
 *
 * <pre>{@code
 * #  MANDATORY HEADER (Not compress, not encrypted.
 * #  4s     h         Q        16s         Q
 * # 'CART<VERSION><RESERVED><ARC4KEY><OPT_HEADER_LEN>'
 * #
 * # OPTIONAL_HEADER (OPT_HEADER_LEN bytes)
 * # RC4(<JSON_SERIALIZED_OPTIONAL_HEADER>)
 * #
 * # RC4(ZLIB(block encoded stream ))
 * #
 * # OPTIONAL_FOOTER_LEN (Q)
 * # <JSON_SERIALIZED_OPTIONAL_FOOTER>
 * #
 * #  MANDATORY FOOTER
 * #  4s      QQ           Q
 * # 'TRAC<RESERVED><OPT_FOOTER_LEN>'
 * }</pre>
 * Where s=1 ASCII string byte, h=short, Q=quadword
 * <p>
 * Note: There is an error in the documented mandatory footer. the 'QQ' marked
 * as reserved should be two separate 'Q' sized values, the first is actually
 * reserved (0) and the second is the position of the optional footer.
 */
public final class CartV1Constants {
	/**
	 * Header magic value for CaRT
	 */
	public static final String HEADER_MAGIC = "CART";

	/**
	 * Version number required for CaRT version 1
	 */
	public static final short HEADER_VERSION = 1;

	/**
	 * Header reserved, required value
	 */
	public static final long HEADER_RESERVED = 0;

	/**
	 * Length of the mandatory CaRT header
	 */
	public static final int HEADER_LENGTH = 4 + 2 + 8 + 16 + 8;

	/**
	 * Footer magic value for CaRT
	 */
	public static final String FOOTER_MAGIC = "TRAC";

	/**
	 * Footer reserved, required value
	 */
	public static final long FOOTER_RESERVED = 0;

	/**
	 * Length of the mandatory CaRT footer
	 */
	public static final int FOOTER_LENGTH = 4 + 8 + 8 + 8;

	/**
	 * Length of the CaRT ARC4 key in bytes
	 */
	public static final int ARC4_KEY_LENGTH = 16;

	/**
	 * The default ARC4 key used by CaRT if not overridden with a private value.
	 * Consists of the first 8 digits of PI, twice
	 */
	public static final byte[] DEFAULT_ARC4_KEY = {
		// First 8
		(byte) 0x03, (byte) 0x01, (byte) 0x04, (byte) 0x01,
		(byte) 0x05, (byte) 0x09, (byte) 0x02, (byte) 0x06,
		// Repeat
		(byte) 0x03, (byte) 0x01, (byte) 0x04, (byte) 0x01,
		(byte) 0x05, (byte) 0x09, (byte) 0x02, (byte) 0x06
	};

	/**
	 * The placeholder value that will be stored in the ARC4 key header position when a
	 * private value is in use. Consists of all 16, 0x00 bytes.
	 */
	public static final byte[] PRIVATE_ARC4_KEY_PLACEHOLDER = {
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
	};

	/**
	 * Block size, in bytes, used for reading/writing payload data in CaRT
	 */
	public static final int BLOCK_SIZE = 64 * 1024;

	/**
	 * Minimum length, in bytes, of a CaRT file.
	 * Really it should be longer for the payload bytes themselves. This value only accounts for
	 * the mandatory header and footer.
	 */
	public static final int MINIMUM_LENGTH = HEADER_LENGTH + FOOTER_LENGTH;

	/**
	 * Map of CaRT optional footer hash name keys to MessageDigest hash names.
	 * These are the hashes that are expected to be in a normal CaRT based on the default library
	 * implementation.
	 */
	public static final Map<String, String> EXPECTED_HASHES = new LinkedHashMap<>() {
		{
			put("md5", HashUtilities.MD5_ALGORITHM);
			// SHA1 is not exported in the static variables of the HashUtilities class, but
			// is valid to the underlying MessageDigest
			put("sha1", "SHA1");
			put("sha256", HashUtilities.SHA256_ALGORITHM);
		}
	};

	/**
	 * Set of keys (in lower case) that should only ever exist in the footer. Finding them
	 * in the header could indicate an attempt to obfuscate the true value from the footer.
	 */
	public static final Set<String> FOOTER_ONLY_KEYS = new HashSet<>() {
		{
			add("length");
			addAll(CartV1Constants.EXPECTED_HASHES.keySet()
					.stream()
					.map(String::toLowerCase)
					.collect(Collectors.toList()));
		}
	};
	

	/**
	 * First two header bytes for ZLIB in 3 modes: fast, default, and best compression.
	 */
	public static final List<byte[]> ZLIB_HEADER_BYTES = List.of(
		new byte[] { (byte) 0x78, (byte) 0x01 }, // Fast
		new byte[] { (byte) 0x78, (byte) 0x9c }, // Default
		new byte[] { (byte) 0x78, (byte) 0xda }  // Best
	);	
}
