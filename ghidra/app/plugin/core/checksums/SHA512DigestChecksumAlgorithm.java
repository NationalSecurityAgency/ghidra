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
package ghidra.app.plugin.core.checksums;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class is used for the computation of the SHA-512 checksum algorithm.
 */
public class SHA512DigestChecksumAlgorithm extends DigestChecksumAlgorithm {

	/**
	 * Constructor for the SHA-512 checksum algorithm.
	 * 
	 * @throws NoSuchAlgorithmException If MessageDigest does not support this algorithm.
	 * @see MessageDigest#getInstance(String)
	 */
	public SHA512DigestChecksumAlgorithm() throws NoSuchAlgorithmException {
		super("SHA-512");
	}
}
