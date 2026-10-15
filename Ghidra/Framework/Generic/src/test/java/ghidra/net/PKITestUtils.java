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
import java.math.BigInteger;
import java.security.*;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import ghidra.util.exception.AssertException;

public class PKITestUtils {

	private static final AtomicLong CERTIFICATE_SERIAL = new AtomicLong();

	private PKITestUtils() {
		// no construct
	}

	/**
	 * Generate a certificate fixture using existing keys. CA certificates permit certificate
	 * signing; other certificates permit digital signatures. The issuer name and signing key
	 * are independent so tests can deliberately construct invalid chains.
	 *
	 * @param subject subject common name
	 * @param key subject key pair
	 * @param issuer issuer common name
	 * @param signer key pair used to sign the certificate
	 * @param ca whether the certificate is a CA
	 * @param expired whether the certificate expired an hour ago rather than expiring tomorrow
	 * @return generated certificate
	 * @throws Exception if certificate construction or signing fails
	 */
	public static X509Certificate certificate(String subject, KeyPair key, String issuer,
			KeyPair signer, boolean ca, boolean expired) throws Exception {
		return certificate(subject, key, issuer, signer, new BasicConstraints(ca),
			ca ? KeyUsage.keyCertSign : KeyUsage.digitalSignature, expired);
	}

	/**
	 * Generate a certificate fixture with explicit CA constraints and key usage. This permits
	 * negative tests to construct certificates with inconsistent extensions or signing keys.
	 * Serial numbers are unique within this helper's lifetime, including concurrent callers.
	 *
	 * @param subject subject common name
	 * @param key subject key pair
	 * @param issuer issuer common name
	 * @param signer key pair used to sign the certificate
	 * @param constraints CA indication and optional path-length constraint
	 * @param usage bit mask of {@link KeyUsage} flags
	 * @param expired whether the certificate expired an hour ago rather than expiring tomorrow
	 * @return generated certificate, valid from yesterday until the selected expiration time
	 * @throws Exception if certificate construction or signing fails
	 */
	public static X509Certificate certificate(String subject, KeyPair key, String issuer,
			KeyPair signer, BasicConstraints constraints, int usage, boolean expired)
			throws Exception {
		long now = System.currentTimeMillis();
		Date start = new Date(now - 86400000L);
		Date end = new Date(now + (expired ? -3600000L : 86400000L));
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			new X500Name("CN=" + issuer), BigInteger.valueOf(CERTIFICATE_SERIAL.incrementAndGet()),
			start, end, new X500Name("CN=" + subject), key.getPublic());
		builder.addExtension(Extension.basicConstraints, true, constraints);
		builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
		return new JcaX509CertificateConverter().getCertificate(builder.build(
			new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())));
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
