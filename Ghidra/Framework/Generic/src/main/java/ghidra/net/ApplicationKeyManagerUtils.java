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

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyStore.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import javax.net.ssl.*;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import generic.random.SecureRandomFactory;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * <code>ApplicationKeyManagerUtils</code> provides public methods for utilizing
 * the application PKI key management, including access to trusted issuers
 * (i.e., CA certificates), token signing and validation, and the ability to
 * generate keystores for testing or when a self-signed certificate will
 * suffice.
 */
public class ApplicationKeyManagerUtils {

	public static final String RSA_TYPE = "RSA";

	private static final int KEY_SIZE = 4096;

	private static final String SIGNING_ALGORITHM = "SHA512withRSA";

	private static final int MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

	public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERT = "-----END CERTIFICATE-----";

	static {
		/**
		 * Bouncy Castle uses its BCStyle for X500Names which reverses Distingushed Name ordering.
		 * This is resolved by setting the default to RFC4519 style to ensure compatibility with 
		 * Java's internal implementation of X500Name.
		 * <p>
		 * Note that this could become an issue if this static default is adjusted elsewhere.
		 * It may be neccessary to set this at the start of all methods which rely on any of the
		 * BC code for X500 certificate processing.
		 * 
		 */
		X500Name.setDefaultStyle(RFC4519Style.INSTANCE);
	}

	private ApplicationKeyManagerUtils() {
		// no instantiation - static methods only
	}

	/**
	 * Sign the supplied token byte array using an installed certificate from
	 * one of the specified authorities
	 * @param authorities trusted certificate authorities
	 * @param token token byte array
	 * @return signed token object
	 * @throws NoSuchAlgorithmException algorithym associated within signing certificate not found
	 * @throws SignatureException failed to generate SignedToken
	 * @throws CertificateException error associated with signing certificate
	 */
	public static SignedToken getSignedToken(Principal[] authorities, byte[] token)
			throws NoSuchAlgorithmException, SignatureException, CertificateException {

		PrivateKey privateKey = null;
		X509Certificate[] certificateChain = null;
		try {
			ApplicationKeyManagerFactory keyManagerFactory =
				ApplicationKeyManagerFactory.getInstance();
			for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
				if (!(keyManager instanceof X509KeyManager)) {
					continue;
				}
				X509KeyManager x509KeyManager = (X509KeyManager) keyManager;
				String alias = x509KeyManager.chooseClientAlias(new String[] { RSA_TYPE },
					authorities, null);
				if (alias != null) {
					privateKey = x509KeyManager.getPrivateKey(alias);
					certificateChain = x509KeyManager.getCertificateChain(alias);
					break;
				}
			}

			if (privateKey == null || certificateChain == null) {
				CertificateException e =
					new CertificateException("suitable PKI certificate not found");
				e.printStackTrace();
				throw e;
			}

			//
			// See JAVA Examples in a Nutshell (p.358) for use of Signer and
			// IdentityScope classes
			//

			String algorithm = certificateChain[0].getSigAlgName();
			Signature sig = Signature.getInstance(algorithm);
			try {
				sig.initSign(privateKey);
			}
			catch (InvalidKeyException e) {
				throw new CertificateException("suitable PKI certificate not found", e);
			}
			sig.update(token);

			return new SignedToken(token, sig.sign(), certificateChain, algorithm);
		}
		finally {
			if (privateKey != null) {
				// Note: Keystore destroy only supported in Java 1.8
				try {
					privateKey.destroy();
				}
				catch (DestroyFailedException e) {
					// ignore - may not be supported by all keystores
				}
			}
		}
	}

	/**
	 * Verify that the specified sigBytes reflect my signature of the specified
	 * token.
	 * @param authorities trusted certificate authorities
	 * @param token byte array token
	 * @param signature token signature
	 * @return true if signature is my signature
	 * @throws NoSuchAlgorithmException algorithym associated within signing certificate not found
	 * @throws SignatureException failed to generate SignedToken
	 * @throws CertificateException error associated with signing certificate
	 */
	public static boolean isMySignature(Principal[] authorities, byte[] token, byte[] signature)
			throws NoSuchAlgorithmException, SignatureException, CertificateException {
		SignedToken signedToken = getSignedToken(authorities, token);
		return Arrays.equals(signature, signedToken.signature);
	}

	/**
	 * Returns a list of trusted issuers (i.e., CA certificates) as established
	 * by the {@link ApplicationTrustManagerFactory}.
	 * @return array of trusted Certificate Authorities
	 * @throws CertificateException if failed to properly initialize trust manager
	 * due to CA certificate error(s).
	 */
	public static X500Principal[] getTrustedIssuers() throws CertificateException {

		TrustManager[] trustManagers = ApplicationTrustManagerFactory.getTrustManagers();
		if (ApplicationTrustManagerFactory.hasCertError()) {
			throw new CertificateException("failed to load CA certs",
				ApplicationTrustManagerFactory.getCertError());
		}

		Set<X500Principal> set = new HashSet<>();

		boolean openTrust = true;
		for (TrustManager trustManager : trustManagers) {
			if (!(trustManager instanceof X509TrustManager)) {
				Msg.warn(ApplicationKeyManagerUtils.class,
					"Unexpected trust manager implementation: " +
						trustManager.getClass().getName());
				openTrust = false;
				continue;
			}
			X509TrustManager x509TrustManager = (X509TrustManager) trustManager;
			X509Certificate[] acceptedIssuers = x509TrustManager.getAcceptedIssuers();
			if (acceptedIssuers != null) {
				openTrust = false;
				for (X509Certificate trustedCert : acceptedIssuers) {
					set.add(trustedCert.getSubjectX500Principal());
				}
			}
		}

		if (openTrust) {
			return null;// trust all authorities
		}

		X500Principal[] principals = new X500Principal[set.size()];
		return set.toArray(principals);
	}

	/**
	 * Validate a client certificate ensuring that it is not expired and is
	 * trusted based upon the active trust managers.
	 * @param certChain X509 certificate chain
	 * @param authType authentication type (i.e., "RSA")
	 * @throws CertificateException if certificate validation fails
	 */
	public static void validateClient(X509Certificate[] certChain, String authType)
			throws CertificateException {

		CertificateException checkFailure = null;

		TrustManager[] trustManagers = ApplicationTrustManagerFactory.getTrustManagers();
		if (ApplicationTrustManagerFactory.hasCertError()) {
			throw new CertificateException("failed to load CA certs",
				ApplicationTrustManagerFactory.getCertError());
		}

		for (TrustManager trustManager : trustManagers) {
			if (!(trustManager instanceof X509TrustManager)) {
				continue;
			}
			X509TrustManager x509TrustManager = (X509TrustManager) trustManager;

			try {
				x509TrustManager.checkClientTrusted(certChain, authType);
				checkFailure = null;
				break;
			}
			catch (CertificateException e) {
				checkFailure = e;
			}
		}
		if (checkFailure != null) {
			throw checkFailure;// check failed - throw last failure
		}
	}

	/**
	 * Pack ordered list of certs to create a certificate chain array
	 * @param cert primary certificate
	 * @param caCerts CA certificate chain.
	 * @return ordered certificate chain
	 */
	private static Certificate[] makeCertificateChain(Certificate cert, Certificate... caCerts) {
		Certificate[] chain = new Certificate[caCerts.length + 1];
		chain[0] = cert;
		System.arraycopy(caCerts, 0, chain, 1, caCerts.length);
		return chain;
	}

	/**
	 * Export X.509 certificates to the specified outFile.
	 * @param certificates certificates to be stored 
	 * @param outFile output file
	 * @throws IOException if error occurs writing to outFile
	 * @throws CertificateEncodingException if error occurs while encoding certificate data
	 */
	public static void exportX509Certificates(Certificate[] certificates, File outFile)
			throws IOException, CertificateEncodingException {

		try (FileOutputStream fout = new FileOutputStream(outFile);
				PrintWriter writer = new PrintWriter(fout)) {
			for (Certificate certificate : certificates) {
				if (!(certificate instanceof X509Certificate)) {
					continue;
				}
				writer.println(BEGIN_CERT);
				String base64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
				while (base64.length() != 0) {
					int endIndex = Math.min(44, base64.length());
					String line = base64.substring(0, endIndex);
					writer.println(line);
					base64 = base64.substring(endIndex);
				}
				writer.println(END_CERT);
				writer.println();
			}
		}
	}

	/**
	 * Generate a new {@link X509Certificate} with RSA {@link KeyPair} and create/update a {@link KeyStore}
	 * optionally backed by a keyFile.  
	 * @param alias entry alias with keystore
	 * @param dn distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
	 * @param durationDays number of days which generated certificate should remain valid
	 * @param caEntry optional CA private key entry.  If null, a self-signed CA certificate will be generated.
	 * @param keyFile optional file to load/store resulting {@link KeyStore} (may be null)
	 * @param keystoreType support keystore type (e.g., "JKS", "PKCS12")
	 * @param protectedPassphrase key and keystore protection password
	 * @return keystore containing newly generated certification with key pair
	 * @throws KeyStoreException if error occurs while updating keystore
	 */
	public static final KeyStore createKeyStore(String alias, String dn, int durationDays,
			PrivateKeyEntry caEntry, File keyFile, String keystoreType, char[] protectedPassphrase)
			throws KeyStoreException {

		PasswordProtection pp = new PasswordProtection(protectedPassphrase);

		LoadStoreParameter loadStoreParameter = null;
		if (keyFile != null && keyFile.exists()) {
			loadStoreParameter = new LoadStoreParameter() {
				@Override
				public ProtectionParameter getProtectionParameter() {
					return pp;
				}
			};
		}

		try {
			KeyStore keyStore = KeyStore.getInstance(keystoreType);
			keyStore.load(loadStoreParameter);

			SecureRandom random = SecureRandomFactory.getSecureRandom();

			KeyPairGenerator rsa = KeyPairGenerator.getInstance(RSA_TYPE);
			rsa.initialize(KEY_SIZE);

			KeyPair keyPair = rsa.generateKeyPair();
			PrivateKey issuerKey = keyPair.getPrivate();

			byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
			SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(encodedPublicKey);

			X500Name x500Name = new X500Name(dn);
			X500Name caX500Name = x500Name; // self-signed CA if caEntry is null
			KeyUsage keyUsage = new KeyUsage(
				KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyCertSign);
			if (caEntry != null) {
				// derive CA X500Name from caEntry
				Certificate caCert = caEntry.getCertificate();
				if (!(caCert instanceof X509Certificate)) {
					throw new CertificateException(
						"Unsupported certificate type: " + caCert.getType());
				}
				X509Certificate caX509Cert = (X509Certificate) caCert;
				caX500Name =
					new X500Name(caX509Cert.getSubjectDN().getName());
				keyUsage = new KeyUsage(
					KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
				issuerKey = caEntry.getPrivateKey();
			}
			Date notBefore = new Date();
			long durationMs = (long) durationDays * MILLISECONDS_PER_DAY;
			Date notAfter = new Date(notBefore.getTime() + durationMs);
			BigInteger serialNumber = new BigInteger(128, random);
			
//			JcaX509ExtensionUtils x509Utils = new JcaX509ExtensionUtils();
			
			X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caX500Name,
				serialNumber, notBefore, notAfter, x500Name, bcPk);
			certificateBuilder
//					.addExtension(Extension.subjectKeyIdentifier, true, x509Utils.createSubjectKeyIdentifier(bcPk))
					.addExtension(Extension.keyUsage, true, keyUsage);
			
			if (caEntry == null) {
				certificateBuilder
						.addExtension(Extension.basicConstraints, true, new BasicConstraints(1));
//						.addExtension(Extension.authorityKeyIdentifier, true, x509Utils.createAuthorityKeyIdentifier(bcPk));
			}
			
			ContentSigner contentSigner =
				new JcaContentSignerBuilder(SIGNING_ALGORITHM).build(issuerKey);

			X509Certificate certificate = new JcaX509CertificateConverter()
					.getCertificate(certificateBuilder.build(contentSigner));

			Certificate[] chain;
			if (caEntry == null) {
				chain = new Certificate[] { certificate };
			}
			else {
				chain = makeCertificateChain(certificate, caEntry.getCertificateChain());
			}

			keyStore.setKeyEntry(alias, keyPair.getPrivate(), protectedPassphrase, chain);

			if (keyFile != null) {
				FileOutputStream out = new FileOutputStream(keyFile);
				try {
					keyStore.store(out, protectedPassphrase);
					out.flush();
					out.getFD().sync();
					Msg.debug(ApplicationKeyManagerUtils.class,
						out.getChannel().size() + " bytes written to key/cert file: " + keyFile);
				}
				catch (SyncFailedException e) {
					// ignore
				}
				finally {
					out.close();
				}
				keyFile.setReadable(true, true);
				keyFile.setWritable(false);
			}

			Msg.debug(ApplicationKeyManagerUtils.class,
				"Certificate Generated (" + alias + "): " + dn);

			return keyStore;
		}
		catch (GeneralSecurityException | OperatorException | IOException e) {
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

	/**
	 * Generate a new {@link X509Certificate} with RSA {@link KeyPair} and create/update a {@link KeyStore}
	 * optionally backed by a keyFile.  
	 * @param alias entry alias with keystore
	 * @param dn distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
	 * @param durationDays number of days which generated certificate should remain valid
	 * @param caEntry optional CA private key entry.  If null, a self-signed CA certificate will be generated.
	 * @param keyFile optional file to load/store resulting {@link KeyStore} (may be null)
	 * @param keystoreType support keystore type (e.g., "JKS", "PKCS12")
	 * @param protectedPassphrase key and keystore protection password
	 * @return newly generated keystore entry with key pair
	 * @throws KeyStoreException if error occurs while updating keystore
	 */
	public static final PrivateKeyEntry createKeyEntry(String alias, String dn, int durationDays,
			PrivateKeyEntry caEntry, File keyFile, String keystoreType, char[] protectedPassphrase)
			throws KeyStoreException {

		PasswordProtection pp = new PasswordProtection(protectedPassphrase);
		try {
			KeyStore keyStore = createKeyStore(alias, dn, durationDays, caEntry, keyFile,
				keystoreType, protectedPassphrase);
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
