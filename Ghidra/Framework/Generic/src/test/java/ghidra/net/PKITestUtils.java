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

import java.io.File;
import java.security.*;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.asn1.x509.KeyUsage;

import ghidra.util.exception.AssertException;

public class PKITestUtils {

	private PKITestUtils() {
		// no construct
	}
	
	/**
	 * Generate a new {@link X509Certificate} with RSA {@link KeyPair} and create/update a {@link KeyStore}
	 * optionally backed by a keyFile. 
	 * <p>
	 * Standard usage will include {@link KeyUsage#digitalSignature} and {@link KeyUsage#keyEncipherment}.
	 * For non-CA extended usage will include serverAuth and clientAuth for maximum compatibility. 
	 * 
	 * @param alias entry alias with keystore
	 * @param dn distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
	 * @param durationDays number of days which generated certificate should remain valid
	 * @param caEntry optional CA private key entry (issuer of new certificate).  If null, new 
	 *          certificate will sign itself (self-signed).
	 * @param isCA if true the new certificate will tagged as a CA
	 * @param keyFile optional file to load/store resulting {@link KeyStore} (may be null)
	 * @param keystoreType support keystore type (e.g., "JKS", "PKCS12")
	 * @param subjectAlternativeNames an optional list of subject alternative names to be included 
	 * 			in certificate (may be null)
	 * @param protectedPassphrase key and keystore protection password
	 * @return newly generated keystore entry with key pair
	 * @throws KeyStoreException if error occurs while updating keystore
	 */
	public static final PrivateKeyEntry createKeyEntry(String alias, String dn, int durationDays,
			PrivateKeyEntry caEntry, boolean isCA, File keyFile, String keystoreType,
			Collection<String> subjectAlternativeNames, char[] protectedPassphrase)
			throws KeyStoreException {

		PasswordProtection pp = new PasswordProtection(protectedPassphrase);
		try {
			KeyStore keyStore = PKIUtils.createKeyStore(alias, dn, durationDays, caEntry, isCA, keyFile,
				keystoreType, subjectAlternativeNames, protectedPassphrase);
			return (PrivateKeyEntry) keyStore.getEntry(alias, pp);
		}
		catch (NoSuchAlgorithmException | UnrecoverableEntryException e) {
			throw new KeyStoreException("Failed to generate/store certificate (" + dn + ")", e);
		}
		finally {
			try {
				pp.destroy();
			}
			catch (DestroyFailedException e) {
				throw new AssertException(e); // unexpected for simple password clearing
			}
		}
	}
}
