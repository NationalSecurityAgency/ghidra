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
import javax.swing.filechooser.FileNameExtensionFilter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.RFC4519Style;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.IPAddress;

import generic.random.SecureRandomFactory;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * {@link PKIUtils} provides supporting utilities for creating and accessing X509 certificate
 * keystore files.
 */
public class PKIUtils {

	public static final String RSA_TYPE = "RSA";

	private static final int KEY_SIZE = 4096;

	private static final String SIGNING_ALGORITHM = "SHA512withRSA";

	private static final int MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

	public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERT = "-----END CERTIFICATE-----";

	public static final String[] PKCS_FILE_EXTENSIONS = new String[] { "p12", "pks", "pfx" };
	public static final FileNameExtensionFilter PKCS_FILENAME_FILTER =
		new FileNameExtensionFilter("PKCS Key File", PKCS_FILE_EXTENSIONS);

	static {
		/**
		 * Bouncy Castle uses its BCStyle for X500Names which reverses Distinguished Name ordering.
		 * This is resolved by setting the default to RFC4519 style to ensure compatibility with 
		 * Java's internal implementation of X500Name.
		 * <p>
		 * Note that this could become an issue if this static default is adjusted elsewhere.
		 * It may be necessary to set this at the start of all methods which rely on any of the
		 * BC code for X500 certificate processing.
		 * 
		 */
		X500Name.setDefaultStyle(RFC4519Style.INSTANCE);
	}

	/**
	 * Establish X509TrustManager for the specified CA certificate storage.
	 * 
	 * @param caCertsFile CA certificates storage file
	 * @return X509TrustManager
	 * @throws CancelledException if password entry was cancelled
	 * @throws GeneralSecurityException if error occured during truststore initialization
	 * @throws IOException if file read error occurs
	 */
	public static X509TrustManager getTrustManager(File caCertsFile)
			throws CancelledException, GeneralSecurityException, IOException {

		if (!caCertsFile.isFile()) {
			throw new FileNotFoundException(
				"CA Certificates file not found: " + caCertsFile.getAbsolutePath());
		}

		KeyStore keyStore = PKIUtils.loadCertificateStore(caCertsFile.getAbsolutePath());
		TrustManagerFactory tmf =
			TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		tmf.init(keyStore);

		X509TrustManager trustManager = null;
		TrustManager[] trustManagers = tmf.getTrustManagers();
		for (TrustManager trustManager2 : trustManagers) {
			if (trustManager2 instanceof X509TrustManager mgr) {
				//ApplicationKeyStore.logCerts(mgr.getAcceptedIssuers());
				trustManager = mgr;
				break;
			}
		}

		if (trustManager == null) {
			throw new CertStoreException(
				"Failed to load X509 TrustManager from " + caCertsFile.getAbsolutePath());
		}

		return trustManager;
	}

	/**
	 * Pack ordered list of certs to create a certificate chain array
	 * 
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
	 * 
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
	 * 
	 * @param alias entry alias with keystore
	 * @param dn distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
	 * @param durationDays number of days which generated certificate should remain valid
	 * @param caEntry optional CA private key entry.  If null, a self-signed CA certificate will be 
	 * 			generated.
	 * @param keyFile optional file to load/store resulting {@link KeyStore} (may be null)
	 * @param keystoreType support keystore type (e.g., "JKS", "PKCS12")
	 * @param subjectAlternativeNames an optional list of subject alternative names to be included 
	 * 			in certificate (may be null)
	 * @param protectedPassphrase key and keystore protection password
	 * @return keystore containing newly generated certification with key pair
	 * @throws KeyStoreException if error occurs while updating keystore
	 */
	public static final KeyStore createKeyStore(String alias, String dn, int durationDays,
			PrivateKeyEntry caEntry, File keyFile, String keystoreType,
			Collection<String> subjectAlternativeNames, char[] protectedPassphrase)
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
				caX500Name = new X500Name(caX509Cert.getSubjectX500Principal().getName());
				keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
				issuerKey = caEntry.getPrivateKey();
			}
			Date notBefore = new Date();
			long durationMs = (long) durationDays * MILLISECONDS_PER_DAY;
			Date notAfter = new Date(notBefore.getTime() + durationMs);
			BigInteger serialNumber = new BigInteger(128, random);

			X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caX500Name,
				serialNumber, notBefore, notAfter, x500Name, bcPk);
			certificateBuilder.addExtension(Extension.keyUsage, true, keyUsage);
			if (subjectAlternativeNames != null && !subjectAlternativeNames.isEmpty()) {
				List<GeneralName> nameList = new ArrayList<GeneralName>();
				for (String altName : subjectAlternativeNames) {
					int nameType =
						IPAddress.isValid(altName) ? GeneralName.iPAddress : GeneralName.dNSName;
					nameList.add(new GeneralName(nameType, altName));
				}
				GeneralName[] altNames = nameList.toArray(GeneralName[]::new);
				certificateBuilder.addExtension(Extension.subjectAlternativeName, false,
					new GeneralNames(altNames));
			}
			if (caEntry == null) {
				certificateBuilder.addExtension(Extension.basicConstraints, true,
					new BasicConstraints(1));
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
					Msg.debug(PKIUtils.class,
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

			Msg.debug(PKIUtils.class, "Certificate Generated (" + alias + "): " + dn);

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
	 * 
	 * @param alias entry alias with keystore
	 * @param dn distinguished name (e.g., "CN=Ghidra Test, O=Ghidra, OU=Test, C=US" )
	 * @param durationDays number of days which generated certificate should remain valid
	 * @param caEntry optional CA private key entry.  If null, a self-signed CA certificate will be generated.
	 * @param keyFile optional file to load/store resulting {@link KeyStore} (may be null)
	 * @param keystoreType support keystore type (e.g., "JKS", "PKCS12")
	 * @param subjectAlternativeNames an optional list of subject alternative names to be included 
	 * 			in certificate (may be null)
	 * @param protectedPassphrase key and keystore protection password
	 * @return newly generated keystore entry with key pair
	 * @throws KeyStoreException if error occurs while updating keystore
	 */
	public static final PrivateKeyEntry createKeyEntry(String alias, String dn, int durationDays,
			PrivateKeyEntry caEntry, File keyFile, String keystoreType,
			Collection<String> subjectAlternativeNames, char[] protectedPassphrase)
			throws KeyStoreException {

		PasswordProtection pp = new PasswordProtection(protectedPassphrase);
		try {
			KeyStore keyStore = createKeyStore(alias, dn, durationDays, caEntry, keyFile,
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

	/**
	 * Load the all certificates from the specified certificate store in a standard
	 * X.509 form (e.g., concatenation of Base64 encoded certificates: *.pem, *.crt, *.cer, *.der) 
	 * or Java JKS (*.jks) form.
	 * 
	 * @param certsPath certificate(s) storage file path
	 * @return KeyStore containing certificates
	 * @throws IOException if failure occurred reading and processing keystore file.
	 * @throws NoSuchAlgorithmException if the algorithm used to check the integrity of the 
	 * 			keystore cannot be found
	 * @throws CertificateException if any of the certificates in the keystore could not be loaded 
	 * @throws KeyStoreException if a general error occurred opening/processing keystore
	 */
	public static KeyStore loadCertificateStore(String certsPath)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

		int certCount = 0;

		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		store.load(null);

		// Attempt to read certificates in Base64 encoded form
		InputStream fis = new FileInputStream(certsPath);
		BufferedInputStream bis = new BufferedInputStream(fis);

		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			while (bis.available() > 0) {
				try {
					Certificate cert = cf.generateCertificate(bis);
					if (cert instanceof X509Certificate) {
						X509Certificate x509Cert = (X509Certificate) cert;
						String name = getCommonName(x509Cert.getSubjectX500Principal());
						store.setCertificateEntry(name, cert);
						++certCount;
					}
				}
				catch (CertificateException e) {
					// Must handle blank lines at bottom of file
					Throwable cause = e.getCause();
					if (cause != null && "Empty input".equals(cause.getMessage())) {
						break; // end of file
					}
					throw e;
				}
			}
		}
		finally {
			bis.close();
		}

		if (certCount == 0) {
			// Processing JKS files above produce "Empty input", if no certs read
			// try reading as keystore without password 
			return getKeyStoreInstance(certsPath, null);
		}
		return store;
	}

	/**
	 * Attempt to load a client/server keystore in a PKCS12 form (*.p12, *.pks, *.pfx) or 
	 * Java JKS (*.jks) form.
	 * 
	 * @param keystorePath JKS or PKCS12 keystore file path
	 * @param password keystore password
	 * @return keystore instance
	 * @throws IOException if failure occurred reading and processing keystore file or if the 
	 * 			given password was incorrect. If the error is due to a wrong password, the 
	 * 			{@link Throwable#getCause cause} of the {@code IOException} should be an
	 * 			{@code UnrecoverableKeyException}
	 * @throws NoSuchAlgorithmException if the algorithm used to check the integrity of the 
	 * 			keystore cannot be found
	 * @throws CertificateException if any of the certificates in the keystore could not be loaded 
	 * @throws KeyStoreException if a general error occurred opening/processing keystore
	 */
	public static synchronized KeyStore getKeyStoreInstance(String keystorePath, char[] password)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

		String type = PKIUtils.detectKeyStoreType(keystorePath);
		if (type == null) {
			throw new KeyStoreException("Unsupported PKI key store file type: " + keystorePath);
		}

		KeyStore ks = KeyStore.getInstance(type);

		InputStream fis = new FileInputStream(keystorePath);
		BufferedInputStream bis = new BufferedInputStream(fis);
		try {
			ks.load(bis, password);
		}
		finally {
			bis.close();
		}
		return ks;
	}

	/**
	 * Attempt to detect PKI KeyStore type ("JKS" or "PKCS12") for the specified file.
	 * 
	 * @param keystorePath key store file path
	 * @return "JKS", "PKCS12" or null
	 * @throws IOException if file read error occurs
	 */
	public static String detectKeyStoreType(String keystorePath) throws IOException {
		try (FileInputStream fis = new FileInputStream(keystorePath)) {
			byte[] header = new byte[4];
			int read = fis.read(header);
			if (read < 4) {
				return null;
			}

			// Check for JKS magic number: FEEDFEED
			if ((header[0] & 0xFF) == 0xFE && (header[1] & 0xFF) == 0xED &&
				(header[2] & 0xFF) == 0xFE && (header[3] & 0xFF) == 0xED) {
				return "JKS";
			}

			// Check for PKCS12: starts with 0x30 0x82
			if ((header[0] & 0xFF) == 0x30 && (header[1] & 0xFF) == 0x82) {
				return "PKCS12";
			}

			return null;
		}
	}

	/**
	 * Extract Common Name (CN) from specified principal subject Distinguished Name (DN)
	 * 
	 * @param subject X.509 certificate subject
	 * @return Common Name or full subject name if unable to extract CN from DN
	 */
	private static String getCommonName(Principal subject) {

		// Subject name should be distinguished-name (DN) which starts with common-name (CN)
		String name = subject.getName();
		int commaIndex = name.indexOf(',');
		String firstElement = commaIndex < 0 ? name : name.substring(0, commaIndex);

		int equalsIndex = firstElement.indexOf('=');
		if (equalsIndex <= 0) {
			return name; // bad common name
		}

		String fieldName = firstElement.substring(0, equalsIndex).trim();
		String fieldValue = firstElement.substring(equalsIndex + 1).trim();

		if (!fieldName.equalsIgnoreCase("CN")) {
			return name; // bad common name
		}

		return fieldValue;
	}

	/**
	 * Log all X509 certificates contained within keystore
	 * 
	 * @param keyStore certificate keystore
	 */
	static void logCerts(KeyStore keyStore) {
		try {
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				Certificate certificate = keyStore.getCertificate(alias);
				if (certificate == null) {
					continue;
				}
				else if (certificate instanceof X509Certificate) {
					logCert(alias, (X509Certificate) certificate);
				}
				else {
					Msg.warn(PKIUtils.class, "Ignore unrecognized certificate: alias=" + alias +
						", type=" + certificate.getType());
				}
			}
		}
		catch (KeyStoreException e) {
			Msg.error(PKIUtils.class, "KeyStore failure", e);
		}
	}

	/**
	 * Log all X509 certificates contained within array
	 * 
	 * @param x509Certs array of certificates
	 */
	public static void logCerts(X509Certificate[] x509Certs) {
		for (X509Certificate x509Cert : x509Certs) {
			logCert(null, x509Cert);
		}
	}

	/**
	 * Log specified X509 certificate details
	 * 
	 * @param alias certificate alias or null if not applicable
	 * @param x509Cert X509 certificate
	 */
	static void logCert(String alias, X509Certificate x509Cert) {

		X500Principal subj = x509Cert.getSubjectX500Principal();
		X500Principal issuer = x509Cert.getIssuerX500Principal();

		Date now = new Date();

		String label = alias != null ? (alias + ": ") : "";
		if (now.compareTo(x509Cert.getNotAfter()) > 0) {
			Msg.warn(PKIUtils.class,
				"   " + label + getCommonName(subj) + ", issued by " + getCommonName(issuer) +
					", S/N " + x509Cert.getSerialNumber().toString(16) + ", expired " +
					x509Cert.getNotAfter() + " **EXPIRED**");
		}
		else {
			Msg.info(PKIUtils.class,
				"   " + label + getCommonName(subj) + ", issued by " + getCommonName(issuer) +
					", S/N " + x509Cert.getSerialNumber().toString(16) + ", expires " +
					x509Cert.getNotAfter());
		}
	}
}
