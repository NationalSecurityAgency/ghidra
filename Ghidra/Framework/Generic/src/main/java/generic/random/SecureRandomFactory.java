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
package generic.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import ghidra.util.Msg;

/**
 * <code>SecureRandomFactory</code> provides a static singleton instance of SecureRandom
 */
public class SecureRandomFactory {

	private static SecureRandom random;

	private static final String[] preferredAlgorithm =
		new String[] { "NativePRNGNonBlocking", "SHA1PRNG" };

	private static synchronized void initialize() {
		if (random != null) {
			return;
		}
		Msg.info(SecureRandomFactory.class, "Initializing Random Number Generator...");
		for (String algorithm : preferredAlgorithm) {
			try {
				random = SecureRandom.getInstance(algorithm);
				Msg.info(SecureRandomFactory.class,
					"Random Number Generator initialization complete: " + algorithm);
				return;
			}
			catch (NoSuchAlgorithmException e) {
				// ignore
			}
		}
		random = new SecureRandom();
		Msg.info(SecureRandomFactory.class,
			"Random Number Generator initialization complete: default");
	}

	public static SecureRandom getSecureRandom() {
		initialize();
		return random;
	}

	/**
	 * Construction not allowed
	 */
	private SecureRandomFactory() {
		// not used
	}

}
