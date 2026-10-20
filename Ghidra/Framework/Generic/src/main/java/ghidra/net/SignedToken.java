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
package ghidra.net;

import java.security.cert.X509Certificate;

/**
 * <code>SignedToken</code> provides the result of a signed token byte array.
 */
public class SignedToken {
	
	/**
	 * Original token byte array
	 */
	public final byte[] token;
	
	/**
	 * Token byte array signature
	 */
	public final byte[] signature;
	
	/**
	 * Algorithm used for signing
	 */
	public final String algorithm;
	
	/**
	 * Certificate chain with the signing identity first, followed by its issuing CAs.
	 * The root certificate may be omitted.
	 */
	public final X509Certificate[] certChain;

	/**
	 * SignedToken constructor
	 * @param token token byte array
	 * @param signature token byte array signature
	 * @param certChain certificate chain with the signing identity first
	 * @param algorithm algorithm used for signing
	 */
	SignedToken(byte[] token, byte[] signature, X509Certificate[] certChain, String algorithm) {
		this.token = token;
		this.signature = signature;
		this.certChain = certChain;
		this.algorithm = algorithm;
	}
}
