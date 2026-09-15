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
import java.util.function.Consumer;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
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
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import generic.random.SecureRandomFactory;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import utility.function.ExceptionalConsumer;

/**
 * {@link PKIUtils} provides supporting utilities for creating and accessing X509 certificate
 * keystore files.
 */
public class PKIUtils {

	public static final String RSA_TYPE = "RSA";
	public static final String SIGNING_ALGORITHM = "SHA512withRSA";
	public static final int KEY_SIZE = 4096;

	private static final int MILLISECONDS_PER_DAY = 24 * 60 * 60 * 1000;

	public static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERT = "-----END CERTIFICATE-----";

	// PEM block type of an X.509 certificate (see loadX509PemCertificates)
	private static final String CERTIFICATE_PEM_TYPE = "CERTIFICATE";

	/** Java key store type of a JKS key store (see {@link #detectKeyStoreType(String)}) */
	public static final String JKS_TYPE = "JKS";

	/** Java key store type of a PKCS#12 key store (see {@link #detectKeyStoreType(String)}) */
	public static final String PKCS12_TYPE = "PKCS12";

	// Magic number which begins a JKS key store
	private static final byte[] JKS_MAGIC =
		{ (byte) 0xFE, (byte) 0xED, (byte) 0xFE, (byte) 0xED };

	// ASN.1 DER tags relied upon to identify a PKCS#12 key store (see detectKeyStoreType)
	private static final int DER_SEQUENCE_TAG = 0x30;
	private static final int DER_INTEGER_TAG = 0x02;

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
	
	private PKIUtils() {
		// no construct
	}

	/**
	 * Establish X509TrustManager for the specified CA certificate storage.
	 * 
	 * @param caCertsFile CA certificates storage file
	 * @return X509TrustManager
	 * @throws GeneralSecurityException if error occured during truststore initialization
	 * @throws IOException if file read error occurs
	 */
	public static X509TrustManager getTrustManager(File caCertsFile)
			throws GeneralSecurityException, IOException {

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

		// MIME encoder with line length 44 and LF line separator
		Base64.Encoder pemEncoder = Base64.getMimeEncoder(44, new byte[] { '\n' });

		try (PrintWriter writer = new PrintWriter(new FileWriter(outFile))) {
			for (Certificate certificate : certificates) {
				if (certificate instanceof X509Certificate) {
					String encodedCert = pemEncoder.encodeToString(certificate.getEncoded());

					writer.println(BEGIN_CERT);
					writer.println(encodedCert); // MimeEncoder already includes line breaks
					writer.println(END_CERT);
					writer.println();
				}
			}
		}

		outFile.setWritable(false, false);
		outFile.setExecutable(false, false);
	}

	/**
	 * {@return a random certificate serial number}
	 */
	private static final BigInteger generateCertificateSerialNumber() {
	    SecureRandom random = SecureRandomFactory.getSecureRandom();
	    BigInteger serialNumber;

	    do {
	    	// 159 bits guarantees that when converted to a 160-bit (20 byte) 
			// signed BigInteger, the sign bit is always 0 (always positive).
	        serialNumber = new BigInteger(159, random);
	    } while (serialNumber.equals(BigInteger.ZERO)); // Retry if zero

	    return serialNumber;
	}


	/**
	 * {@return the Common Name (CN) for an X509 certificate or null if DN does not contain a CN}
	 * @param cert X509 certificate
	 * @throws InvalidNameException if DN is invalid or contains invalid DN
	 */
	public static String getCommonName(X509Certificate cert) throws InvalidNameException {

		X500Principal subject = cert.getSubjectX500Principal();
		return getCommonName(subject.getName(X500Principal.RFC2253));
	}
	
	/**
	 * {@return the Common Name (CN) for an X509 distinguished name (DN) or null if DN does not contain a CN}
	 * @param distinguishedName distinguished name (DN)
	 * @throws InvalidNameException if DN is invalid or contains invalid CN
	 */
	public static String getCommonName(String distinguishedName) throws InvalidNameException {

		LdapName ldapDN = new LdapName(distinguishedName);

		for (Rdn rdn : ldapDN.getRdns()) {
			if (rdn.getType().equalsIgnoreCase("CN")) {
				String cn = rdn.getValue().toString().trim();
				if (cn.length() == 0) {
					throw new InvalidNameException(
						"Certificate DN specifies an empty Common Name (CN)");
				}
				return cn;
			}
		}
		return null;
	}

	/**
	 * Save a keystore
	 * @param keyStore key store to be saved
	 * @param keyFile file to be written
	 * @param protectedPassphrase protection password
	 * @throws KeyStoreException if error occurred while generating keystore
	 * @throws IOException if failed to write keystore file
	 */
	public static void saveKeyStore(KeyStore keyStore, File keyFile, char[] protectedPassphrase)
			throws KeyStoreException, IOException {
		FileOutputStream out = new FileOutputStream(keyFile);
		try {
			keyStore.store(out, protectedPassphrase);
			out.flush();
			out.getFD().sync();
			Msg.debug(PKIUtils.class,
				out.getChannel().size() + " bytes written to keystore file: " + keyFile);
		}
		catch (SyncFailedException e) {
			// ignore
		}
		catch (GeneralSecurityException e) {
			throw new KeyStoreException("Failed to store keystore", e);
		}
		finally {
			out.close();
		}
		keyFile.setReadable(false, false);
		keyFile.setReadable(true);
		keyFile.setWritable(false, false);
		keyFile.setExecutable(false, false);
	}

	/**
	 * Generate a new {@link X509Certificate} with RSA {@link KeyPair} and create/update a 
	 * {@link KeyStore} optionally backed by a keyFile. 
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
	 * @return keystore containing newly generated certification with key pair
	 * @throws KeyStoreException if error occurs while updating keystore
	 */
	public static final KeyStore createKeyStore(String alias, String dn, int durationDays,
			PrivateKeyEntry caEntry, boolean isCA, File keyFile, String keystoreType,
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

			KeyPairGenerator rsa = KeyPairGenerator.getInstance(RSA_TYPE);
			rsa.initialize(KEY_SIZE);

			KeyPair keyPair = rsa.generateKeyPair();
			PrivateKey issuerKey = keyPair.getPrivate();

			byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
			SubjectPublicKeyInfo bcPk = SubjectPublicKeyInfo.getInstance(encodedPublicKey);

			X500Name x500Name = new X500Name(dn);

			X500Name caX500Name;
			KeyUsage keyUsage;

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
			else {
				// self-signed
				keyUsage = new KeyUsage(
					KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyCertSign);
				caX500Name = x500Name;
			}

			Date notBefore = new Date();
			long durationMs = (long) durationDays * MILLISECONDS_PER_DAY;
			Date notAfter = new Date(notBefore.getTime() + durationMs);
			BigInteger serialNumber = generateCertificateSerialNumber();

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

			// Indicate if this certificate is a CA or not
			certificateBuilder.addExtension(Extension.basicConstraints, true,
				new BasicConstraints(isCA));

			if (!isCA) {
				// For non-CA add extended usage to include client and server authentication
				KeyPurposeId[] usages = new KeyPurposeId[] {
					KeyPurposeId.id_kp_serverAuth, // TLS Web Server Authentication
					KeyPurposeId.id_kp_clientAuth  // TLS Web Client Authentication
				};
				ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(usages);
				certificateBuilder.addExtension(
					Extension.extendedKeyUsage,
					false,
					extendedKeyUsage);
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
				saveKeyStore(keyStore, keyFile, protectedPassphrase);
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

		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		store.load(null);
		
		int certCount = loadX509CertificateStore(certsPath, x509Cert -> {
			String name = getCommonName(x509Cert.getSubjectX500Principal());
			// Ensure a unique alias is used: certificates may share a common name
			// (e.g., a renewed CA) and must not displace each other within the store
			String alias = name;
			for (int i = 2; store.containsAlias(alias); i++) {
				alias = name + "(" + i + ")";
			}
			store.setCertificateEntry(alias, x509Cert);
		});

		if (certCount == 0) {
			// Processing JKS files above produce "Empty input", if no certs read
			// try reading as keystore without password 
			return getKeyStoreInstance(certsPath, null);
		}
		return store;
	}
	
	/**
	 * Load all X.509 certificates from an unencrypted PEM file (a concatenation of Base64 encoded
	 * certificates).  Text surrounding the certificate blocks, such as the certificate details which
	 * some tools emit ahead of each one, is ignored.
	 * <p>
	 * Unlike {@link #loadCertificateStore(String)} this requires the file to be PEM encoded and to
	 * contain nothing but complete certificates, as a certificate authority file must (e.g., the
	 * PostgreSQL {@code ssl_ca_file}) since every entry within it has to be usable: a DER encoded
	 * certificate or a keystore yields no certificates rather than being accepted, and a truncated or
	 * non-certificate PEM block is an error rather than being skipped.
	 *
	 * @param pemFile PEM certificate file
	 * @return the certificates in the order they occur within the file, which is empty if the file
	 * 			contains no PEM block at all
	 * @throws IOException if the file cannot be read or a certificate block is truncated
	 * @throws CertificateException if a PEM block is not a certificate or cannot be decoded
	 */
	public static List<X509Certificate> loadX509PemCertificates(File pemFile)
			throws IOException, CertificateException {
		return loadX509PemCertificates(pemFile, null);
	}

	/**
	 * Read all X509 certificates contained within a PEM encoded file, optionally tolerating any
	 * block which cannot be used.
	 * <p>
	 * Tolerating unusable blocks is appropriate when establishing a trust store, where discarding
	 * every valid certificate on account of one defective block would be the greater failure.  It
	 * is not appropriate when validating a file which the user has supplied for that purpose, where
	 * a defect must be reported rather than passed over - such callers use
	 * {@link #loadX509PemCertificates(File)} instead.
	 *
	 * @param pemFile PEM encoded certificate file
	 * @param unusableBlockConsumer if non-null, a description of each unusable PEM block is passed
	 *   to this consumer and the block is skipped, allowing the remaining certificates to be read.
	 *   If null, the first unusable block is an error.
	 * @return list of X509 certificates read from the file
	 * @throws IOException if the file cannot be read
	 * @throws CertificateException if a block cannot be used and unusableBlockConsumer is null
	 */
	public static List<X509Certificate> loadX509PemCertificates(File pemFile,
			Consumer<String> unusableBlockConsumer) throws IOException, CertificateException {

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		List<X509Certificate> certs = new ArrayList<>();
		try (PemReader reader = new PemReader(new FileReader(pemFile))) {
			int blockNumber = 0;
			for (;;) {
				PemObject pemObject;
				try {
					pemObject = reader.readPemObject();
				}
				catch (DecoderException e) {
					// Base64 decoding failure is reported by BouncyCastle as an unchecked
					// exception.  The offending block has already been consumed through its end
					// marker, so reading is able to continue with the block which follows it.
					++blockNumber;
					String msg = "Invalid PEM certificate data within " + pemFile.getName() + ": " +
						e.getMessage();
					if (unusableBlockConsumer == null) {
						throw new CertificateException(msg);
					}
					unusableBlockConsumer.accept(msg + " (PEM block " + blockNumber + ")");
					continue;
				}
				if (pemObject == null) {
					break;		// end of file
				}
				++blockNumber;
				try {
					certs.add(getX509Certificate(cf, pemObject, pemFile));
				}
				catch (CertificateException e) {
					if (unusableBlockConsumer == null) {
						throw e;
					}
					unusableBlockConsumer
							.accept(e.getMessage() + " (PEM block " + blockNumber + ")");
				}
			}
		}
		return certs;
	}

	/**
	 * Convert a single PEM block into the X509 certificate it contains.
	 * @param cf X509 certificate factory
	 * @param pemObject PEM block which was read
	 * @param pemFile file the block was read from, for error reporting
	 * @return the X509 certificate
	 * @throws CertificateException if the block is not a usable X509 certificate
	 */
	private static X509Certificate getX509Certificate(CertificateFactory cf, PemObject pemObject,
			File pemFile) throws CertificateException {
		if (!CERTIFICATE_PEM_TYPE.equals(pemObject.getType())) {
			throw new CertificateException("Expected only certificates within " +
				pemFile.getName() + ", read PEM block: " + pemObject.getType());
		}
		Certificate cert =
			cf.generateCertificate(new ByteArrayInputStream(pemObject.getContent()));
		if (!(cert instanceof X509Certificate x509Cert)) {
			throw new CertificateException("Unsupported certificate type: " + cert.getType());
		}
		return x509Cert;
	}

	/**
	 * Load the all certificates from the specified certificate store in a standard
	 * X.509 form (e.g., concatenation of Base64 encoded certificates: *.pem, *.crt, *.cer, *.der)
	 * @param certsPath certificate(s) storage file path
	 * @param certConsumer consumer callback to be supplied with each certificate
	 * @return number of X509 certificates read
	 * @throws IOException if failure occurred reading and processing keystore file.
	 * @throws CertificateException if any of the certificates in the keystore could not be loaded 
	 * @throws KeyStoreException thrown by certConsumer
	 */
	public static int loadX509CertificateStore(String certsPath, 
			ExceptionalConsumer<X509Certificate, KeyStoreException> certConsumer) 
			throws IOException, CertificateException, KeyStoreException {

		// Attempt to read certificates in Base64 PEM encoded form
		int certCount = 0;
		try (InputStream fis = new FileInputStream(certsPath); 
				BufferedInputStream bis = new BufferedInputStream(fis)) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			while (bis.available() > 0) {
				try {
					Certificate cert = cf.generateCertificate(bis);
					if (cert instanceof X509Certificate x509Cert) {
						certConsumer.accept(x509Cert);
						++certCount;
					}
				} catch (CertificateException e) {
					// Must handle blank lines at bottom of file
					Throwable cause = e.getCause();
					if (cause != null && "Empty input".equals(cause.getMessage())) {
						break; // end of file
					}
					throw e;
				}
			}
		}
		return certCount;
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
	/**
	 * Determine the Java key store type of a file from its leading bytes.
	 * <p>
	 * Only the Java key store forms are identified.  A certificate file is not a key store and
	 * yields null, which includes a <b>DER</b> encoded certificate: a DER certificate and a PKCS#12
	 * key store cannot be told apart by their leading byte, since both begin with an ASN.1 DER
	 * SEQUENCE (0x30).  They are distinguished here by the first element <i>within</i> that
	 * SEQUENCE, which is an INTEGER version for a PKCS#12 PFX and a nested SEQUENCE
	 * (tbsCertificate) for a certificate:
	 * <pre>
	 *   PFX         ::= SEQUENCE { version INTEGER {v3(3)}, authSafe ContentInfo, ... }
	 *   Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, ... }  -- itself a SEQUENCE
	 * </pre>
	 * Locating that element requires the SEQUENCE length to be decoded, since it may use the DER
	 * long form (the Java default <i>cacerts</i> does).
	 * <p>
	 * This remains a determination based upon the leading bytes and not a full parse, so a caller
	 * must still be prepared for a key store of the identified type to fail to load.
	 *
	 * @param keystorePath path to the file to be examined
	 * @return {@value #JKS_TYPE} or {@value #PKCS12_TYPE} if the file is a Java key store of that
	 *   type, otherwise null (a PEM or DER certificate file among the possibilities)
	 * @throws IOException if the file cannot be read
	 */
	public static String detectKeyStoreType(String keystorePath) throws IOException {

		byte[] header;
		try (InputStream in = new BufferedInputStream(new FileInputStream(keystorePath))) {
			// Sufficient for the JKS magic number, or for a SEQUENCE tag and length (long form of
			// up to 4 length bytes) followed by the first byte of the SEQUENCE content
			header = in.readNBytes(JKS_MAGIC.length + 7);
		}

		if (header.length >= JKS_MAGIC.length &&
			Arrays.equals(JKS_MAGIC, Arrays.copyOf(header, JKS_MAGIC.length))) {
			return JKS_TYPE;
		}

		if (header.length < 2 || (header[0] & 0xFF) != DER_SEQUENCE_TAG) {
			return null;	// not a key store (a PEM certificate file, or unrecognized)
		}

		int contentOffset = derContentOffset(header);
		if (contentOffset < 0 || contentOffset >= header.length) {
			return null;	// truncated, or a length encoding which is not supported
		}

		// A PKCS#12 PFX begins with its INTEGER version, a certificate with its tbsCertificate
		return (header[contentOffset] & 0xFF) == DER_INTEGER_TAG ? PKCS12_TYPE : null;
	}

	/**
	 * Determine the offset of the content which follows the ASN.1 DER tag and length at the start
	 * of the specified data.
	 *
	 * @param der DER encoded data beginning with a tag byte
	 * @return offset of the first content byte, or -1 if the length encoding is unsupported
	 */
	private static int derContentOffset(byte[] der) {
		if (der.length < 2) {
			return -1;
		}
		int length = der[1] & 0xFF;
		if (length < 0x80) {
			return 2;					// short form: the length is held within this byte
		}
		int lengthByteCount = length & 0x7F;
		if (lengthByteCount == 0 || lengthByteCount > 4) {
			return -1;					// indefinite length (invalid in DER), or implausibly large
		}
		return 2 + lengthByteCount;		// long form: length occupies the bytes which follow
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

	private static final String[] KEY_USAGE_NAMES = {
		"DigitalSignature",
		"NonRepudiation",
		"KeyEncipherment",
		"DataEncipherment",
		"KeyAgreement",
		"KeyCertSign",
		"CRLSign",
		"EncipherOnly",
		"DecipherOnly"
	};

	/**
	 * {@return the key-usages as sequence of comma-separated names for a specified certificate}
	 * @param cert x509 certificate
	 */
	public static String formatKeyUsage(X509Certificate cert) {
		boolean[] usage = cert.getKeyUsage();
		if (usage == null) {
			return "No KeyUsage extension present";
		}

		List<String> enabled = new ArrayList<>();
		for (int i = 0; i < usage.length && i < KEY_USAGE_NAMES.length; i++) {
			if (usage[i]) {
				enabled.add(KEY_USAGE_NAMES[i]);
			}
		}

		return String.join(", ", enabled);
	}
}
