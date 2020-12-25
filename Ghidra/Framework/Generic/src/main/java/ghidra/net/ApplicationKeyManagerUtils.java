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
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import javax.net.ssl.*;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.x500.X500Principal;

import generic.random.SecureRandomFactory;
import ghidra.util.Msg;
import sun.security.provider.X509Factory;
import sun.security.x509.*;

/**
 * <code>ApplicationKeyManagerUtils</code> provides public methods for utilizing
 * the application PKI key management, including access to trusted issuers
 * (i.e., CA certificates), token signing and validation, and the ability to
 * generate keystores for testing or when a self-signed certificate will
 * suffice.
 * <p>
 * <b>NOTE:</b> This class makes direct use of classes within the
 * <code>sun.security.x509</code> package thus breaking portability. While this is
 * not preferred, the ability to generate X.509 certificates and keystores
 * appears to be absent from the standard java/javax packages.
 */
public class ApplicationKeyManagerUtils {

	public static final String DEFAULT_SIGNING_ALGORITHM = "SHA1withRSA";

	public static final String DEFAULT_AUTH_TYPE = "RSA";

	private static final int MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

	private ApplicationKeyManagerUtils() {
		// no instantiation - static methods only
	}

	/**
	 * Sign the supplied token byte array using an installed certificate from
	 * one of the specified authorities
	 * @param authorities trusted certificate authorities
	 * @param token token byte array
	 * @return signed token object
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws CertificateException
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
				String alias = x509KeyManager.chooseClientAlias(new String[] { DEFAULT_AUTH_TYPE },
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
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws CertificateException
	 */
	public static boolean isMySignature(Principal[] authorities, byte[] token, byte[] signature)
			throws NoSuchAlgorithmException, SignatureException, CertificateException {
		SignedToken signedToken = getSignedToken(authorities, token);
		return Arrays.equals(signature, signedToken.signature);
	}

	/**
	 * Returns a list of trusted issuers (i.e., CA certificates) as established
	 * by the {@link ApplicationTrustManagerFactory}.
	 * @throws CertificateException
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
	 * @throws CertificateException
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
	 * Pack order list of certs to create a certificate chain array
	 * @param certs certificates which makeup the ordered certificate chain. Null
	 *            certificate elements will be skipped.
	 * @return array of certificates
	 */
	private static Certificate[] getCertificateChain(Certificate... certs) {
		List<Certificate> list = new ArrayList<>();
		for (Certificate cert : certs) {
			if (cert != null) {
				list.add(cert);
			}
		}
		Certificate[] chain = new Certificate[list.size()];
		return list.toArray(chain);
	}

	/**
	 * Generate self-signed PKI X509 keystore containing both a signing key/cert
	 * and an encrypting key/cert.  Default certificte extension specifies key usage of 
	 * Signing which is appropriate for SSL DHE or ECDHE cipher suites.
	 * @param keyFile keystore file or null if not to be stored
	 * @param keystoreType keystore type (e.g., "JKS", "PKCS12")
	 * @param protectedPassphrase passphrase for protecting key and keystore
	 * @param alias for key/cert 
	 * @param certExtensions specifies certificate extensions to be set or null for default
	 *            key usage extension. Only a single alias may be specified when
	 *            this argument is not null.
	 * @param dn distinguished name for principal key holder
	 * @param caSignerKeyEntry certificate issuer/authority (CA) private key entry or null
	 *            for self-signed
	 * @param durationDays number of days from now when certificate shall expire
	 * @return newly generated keystore
	 * @throws KeyStoreException error occurred generating keystore
	 */
	public static KeyStore createKeyStore(File keyFile, String keystoreType,
			char[] protectedPassphrase, String alias, CertificateExtensions certExtensions,
			String dn, PrivateKeyEntry caSignerKeyEntry, int durationDays)
			throws KeyStoreException {

		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance(keystoreType);
			keyStore.load(null);

			addNewKeyPair(keyStore, alias, dn, certExtensions, protectedPassphrase,
				caSignerKeyEntry, durationDays);

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

		}
		catch (GeneralSecurityException | IOException e) {
			throw new KeyStoreException("failed to generate/store certificate (" + dn + ")", e);
		}

		return keyStore;
	}

	/**
	 * Generate a new keypair/certificate and add it to the specified keyStore.
	 * Default certificate extension specifies key usage of digital-signature which is appropriate
	 * for SSL (i.e., DHE or ECDHE cipher suites) and other authentication uses.
	 * @param keyStore key store
	 * @param generator key pair generator
	 * @param alias keypair/certificate alias
	 * @param dn principal distinguished name
	 * @param certExtensions certificate extensions with key usage
	 * @param protectedPassphrase key protection passphrase
	 * @param caSignerKeyEntry certificate issuer/authority (CA) private key
	 *            entry or null for self-signed
	 * @param durationDays number of days from now when certificate shall expire
	 * @throws KeyStoreException error occurred generating keystore
	 */
	private static void addNewKeyPair(KeyStore keyStore, String alias, String dn,
			CertificateExtensions certExtensions, char[] protectedPassphrase,
			PrivateKeyEntry caSignerKeyEntry, int durationDays)
			throws GeneralSecurityException, IOException {

		X509Certificate signerCert = null;
		if (caSignerKeyEntry != null) {
			Certificate cert = caSignerKeyEntry.getCertificate();
			if (!(cert instanceof X509Certificate)) {
				throw new IllegalArgumentException(
					"Unsupported caSignerKeyEntry - X509 certificate required");
			}
			signerCert = (X509Certificate) cert;
		}

		KeyPairGenerator generator = KeyPairGenerator.getInstance(DEFAULT_AUTH_TYPE);
		SecureRandom random = SecureRandomFactory.getSecureRandom();
		generator.initialize(2048, random);

		X509CertInfo certInfo = new X509CertInfo();
		certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));

		certInfo.set(X509CertInfo.ALGORITHM_ID,
			new CertificateAlgorithmId(AlgorithmId.get(DEFAULT_SIGNING_ALGORITHM)));

		certInfo.set(X509CertInfo.SUBJECT + "." + X509CertInfo.DN_NAME, new X500Name(dn)); // requires Java 1.8
		// certInfo.set(X509CertInfo.SUBJECT, new CertificateSubjectName(new X500Name(dn))); // requires Java 1.7

		Date now = new Date(System.currentTimeMillis());
		long durationMs = (long) durationDays * (long) MILLISECONDS_PER_DAY;
		Date end = new Date(now.getTime() + durationMs);
		certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(now, end));
		String issuer = signerCert != null ? signerCert.getSubjectDN().getName() : dn;

		certInfo.set(X509CertInfo.ISSUER + "." + X509CertInfo.DN_NAME, new X500Name(issuer)); // requires Java 1.8 
		// certInfo.set(X509CertInfo.ISSUER, new CertificateIssuerName(new X500Name(issuer))); // requires Java 1.7

		certInfo.set(X509CertInfo.SERIAL_NUMBER,
			new CertificateSerialNumber(random.nextInt() & 0x7fffffff));
		KeyPair keyPair = generator.generateKeyPair();
		certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));

		if (certExtensions == null) {
			// If no extensions specified, set default key usage to digital-signature
			// which is appropriate for SSL and other authentication uses
			certExtensions = new CertificateExtensions();
			KeyUsageExtension keyUsage = new KeyUsageExtension();
			keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, true);
			certExtensions.set(PKIXExtensions.KeyUsage_Id.toString(), keyUsage);
		}
		certInfo.set(X509CertInfo.EXTENSIONS, certExtensions);

		X509CertImpl cert = new X509CertImpl(certInfo);
		PrivateKey caSignerKey =
			caSignerKeyEntry != null ? caSignerKeyEntry.getPrivateKey() : keyPair.getPrivate();
		cert.sign(caSignerKey, DEFAULT_SIGNING_ALGORITHM);
		keyStore.setKeyEntry(alias, keyPair.getPrivate(), protectedPassphrase,
			getCertificateChain(cert, signerCert));
		Msg.debug(ApplicationKeyManagerUtils.class,
			"Certificate Generated (" + alias + "): " + cert.getSubjectDN());
	}

	/**
	 * Export all X.509 certificates contained within keystore to the specified outFile.
	 * @param keystore 
	 * @param outFile output file
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws CertificateEncodingException
	 */
	public static void exportX509Certificates(KeyStore keystore, File outFile)
			throws IOException, KeyStoreException, CertificateEncodingException {
		FileOutputStream fout = new FileOutputStream(outFile);
		PrintWriter writer = new PrintWriter(fout);
		Enumeration<String> aliases = keystore.aliases();
		while (aliases.hasMoreElements()) {
			Certificate certificate = keystore.getCertificate(aliases.nextElement());
			if (!(certificate instanceof X509Certificate)) {
				continue;
			}
			writer.println(X509Factory.BEGIN_CERT);
			String base64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
			while (base64.length() != 0) {
				int endIndex = Math.min(44, base64.length());
				String line = base64.substring(0, endIndex);
				writer.println(line);
				base64 = base64.substring(endIndex);
			}
			writer.println(X509Factory.END_CERT);
			writer.println();
		}
		writer.flush();
		try {
			fout.getFD().sync();
		}
		catch (SyncFailedException e) {
			// ignore
		}
		writer.close();
	}

	/**
	 * Export all X.509 certificates contained within keystore to the specified outFile.
	 * @param keystore 
	 * @param outFile output file
	 * @param password keystore password
	 * @throws CertificateException 
	 * @throws NoSuchAlgorithmException 
	 * @throws FileNotFoundException
	 * @throws KeyStoreException
	 * @throws CertificateEncodingException
	 */
	public static void exportKeystore(KeyStore keystore, File outFile, char[] password)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

		FileOutputStream out = new FileOutputStream(outFile);
		try {
			keystore.store(out, password);
			out.flush();
			out.getFD().sync();
		}
		catch (SyncFailedException e) {
			// ignore
		}
		finally {
			out.close();
		}
	}

}
