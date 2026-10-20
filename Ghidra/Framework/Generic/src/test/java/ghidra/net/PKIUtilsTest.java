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

import static org.junit.Assert.*;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.util.*;

import javax.net.ssl.X509TrustManager;

import org.junit.*;

import generic.test.AbstractGenericTest;
import utilities.util.FileUtilities;

/**
 * Tests for {@link PKIUtils} certificate and key store handling: generation of key stores in each
 * supported format, detection of the format of a file from its content, and the loading of
 * certificates from PEM and DER certificate files and from key stores.
 * <p>
 * Generating an RSA key pair of {@link PKIUtils#KEY_SIZE} bits dominates the cost of these tests
 * (hundreds of milliseconds each), so every certificate which is only ever read is generated once
 * for the class rather than once per test, and the key store files which individual tests merely
 * need to exist are copied from one generated for the class.
 */
public class PKIUtilsTest extends AbstractGenericTest {

	private static final char[] PWD = "!test-password!".toCharArray();

	private static final String CA_DN = "CN=Ghidra Test CA, O=Ghidra, OU=Test, C=US";
	private static final String USER_DN = "CN=Ghidra Test User, O=Ghidra, OU=Test, C=US";

	// Immutable certificate fixtures, generated once for the class
	private static PrivateKeyEntry caEntry;
	private static X509Certificate caCert;
	private static X509Certificate userCert;
	private static X509Certificate renewedCaCert;
	private static X509Certificate otherCaCert;
	private static X509Certificate noCommonNameCert;

	// Key store files generated once for the class and copied by keyStoreFile
	private static File sharedDir;
	private static File sharedPkcs12;
	private static File sharedJks;

	private File tempDir;

	@BeforeClass
	public static void setUpClass() throws Exception {

		// Self-signed CA, and an end-entity certificate which it issues
		caEntry = PKITestUtils.createKeyEntry("ca", CA_DN, 2, null, true, null,
			PKIUtils.PKCS12_TYPE, null, PWD);
		caCert = (X509Certificate) caEntry.getCertificate();

		userCert = (X509Certificate) PKITestUtils.createKeyEntry("user", USER_DN, 2, caEntry, false,
			null, PKIUtils.PKCS12_TYPE, null, PWD).getCertificate();

		// A second, distinct CA which shares the first one's common name
		renewedCaCert = (X509Certificate) PKITestUtils.createKeyEntry("ca2", CA_DN, 2, null, true,
			null, PKIUtils.PKCS12_TYPE, null, PWD).getCertificate();

		// An unrelated CA, which issued none of the certificates above
		otherCaCert = (X509Certificate) PKITestUtils.createKeyEntry("otherca",
			"CN=Other Test CA, O=Ghidra, C=US", 2, null, true, null, PKIUtils.PKCS12_TYPE, null,
			PWD).getCertificate();

		// A certificate whose distinguished name specifies no common name
		noCommonNameCert = (X509Certificate) PKITestUtils.createKeyEntry("nocn", "O=Ghidra, C=US", 2,
			null, false, null, PKIUtils.PKCS12_TYPE, null, PWD).getCertificate();

		// Key store files holding a private key entry, copied per test by keyStoreFile.  These
		// re-use the key pair generated above rather than generating further ones.
		sharedDir = Files.createTempDirectory("pkiutils-shared").toFile();
		sharedPkcs12 = writeSharedKeyStore("shared.p12", PKIUtils.PKCS12_TYPE);
		sharedJks = writeSharedKeyStore("shared.jks", PKIUtils.JKS_TYPE);
	}

	/**
	 * @return a key store of the specified type holding the already-generated key pair under the
	 *   alias "alias", protected by {@link #PWD}
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	private static File writeSharedKeyStore(String name, String keyStoreType) throws Exception {
		File f = new File(sharedDir, name);
		KeyStore ks = KeyStore.getInstance(keyStoreType);
		ks.load(null, null);
		ks.setKeyEntry("alias", caEntry.getPrivateKey(), PWD, caEntry.getCertificateChain());
		try (FileOutputStream out = new FileOutputStream(f)) {
			ks.store(out, PWD);
		}
		return f;
	}

	@AfterClass
	public static void tearDownClass() {
		restoreWritePermission(sharedDir);
		FileUtilities.deleteDir(sharedDir);
	}

	@Before
	public void setUp() throws Exception {
		tempDir = createTempDirectory("pkiutils");
	}

	/**
	 * Restore write permission to everything which was generated, so that the test framework is
	 * able to remove the temporary directory.
	 * <p>
	 * {@link PKIUtils#saveKeyStore(KeyStore, File, char[])} and
	 * {@link PKIUtils#exportX509Certificates(java.security.cert.Certificate[], File)} both clear
	 * write permission on the file they produce.  On Windows that sets the read-only attribute,
	 * which prevents the file from being deleted at all (unlike POSIX, where deletion is governed
	 * by the permissions of the containing directory), leaving the temporary directory behind.
	 * @throws Exception if an unexpected error occurs during cleanup
	 */
	@After
	public void tearDown() throws Exception {
		restoreWritePermission(tempDir);
	}

	private static void restoreWritePermission(File file) {
		if (file == null || !file.exists()) {
			return;
		}
		file.setWritable(true, true);
		File[] children = file.listFiles();
		if (children != null) {
			for (File child : children) {
				restoreWritePermission(child);
			}
		}
	}

	private File file(String name) {
		return new File(tempDir, name);
	}

	/**
	 * Generate a new key store file of the specified type containing a private key entry.  This
	 * incurs a key pair generation and is used only where creating the file is itself under test;
	 * {@link #keyStoreFile(String, String)} is used otherwise.
	 *
	 * @return the generated key store file
	 */
	private File generateKeyStoreFile(String name, String keyStoreType) throws KeyStoreException {
		File f = file(name);
		PKIUtils.createKeyStore("alias", USER_DN, 2, null, false, f, keyStoreType, null, PWD);
		return f;
	}

	/**
	 * @return a copy of the key store generated for the class, of the specified type, holding a
	 *   private key entry under the alias "alias".  A copy is taken rather than generating a new key
	 *   store, since a test which merely requires such a file to exist should not incur a key pair
	 *   generation.
	 */
	private File keyStoreFile(String name, String keyStoreType) throws IOException {
		File shared = PKIUtils.PKCS12_TYPE.equals(keyStoreType) ? sharedPkcs12 : sharedJks;
		File f = file(name);
		Files.copy(shared.toPath(), f.toPath(), StandardCopyOption.REPLACE_EXISTING);
		f.setWritable(true, true);		// the generated key store is read-only
		return f;
	}

	/**
	 * @return a key store file of the specified type holding only trusted certificate entries,
	 *   written with a password (which for PKCS#12 encrypts those entries by default)
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	private File writeCertificateKeyStore(String name, String keyStoreType, X509Certificate... certs)
			throws Exception {
		File f = file(name);
		KeyStore ks = KeyStore.getInstance(keyStoreType);
		ks.load(null, null);
		int i = 0;
		for (X509Certificate cert : certs) {
			ks.setCertificateEntry("ca" + (i++), cert);
		}
		try (FileOutputStream out = new FileOutputStream(f)) {
			ks.store(out, PWD);
		}
		return f;
	}

	private File writeDer(String name, X509Certificate... certs) throws Exception {
		File f = file(name);
		try (FileOutputStream out = new FileOutputStream(f)) {
			for (X509Certificate cert : certs) {
				out.write(cert.getEncoded());
			}
		}
		return f;
	}

	private File writePem(String name, Certificate... certs) throws Exception {
		File f = file(name);
		PKIUtils.exportX509Certificates(certs, f);
		f.setWritable(true, true);		// exportX509Certificates clears write permission
		return f;
	}

	private File writeText(String name, String contents) throws IOException {
		File f = file(name);
		Files.writeString(f.toPath(), contents);
		return f;
	}

	//==================================================================================
	// createKeyStore / getKeyStoreInstance
	//==================================================================================

	@Test
	public void testCreateAndLoadPkcs12KeyStore() throws Exception {
		File f = generateKeyStoreFile("store.p12", PKIUtils.PKCS12_TYPE);
		assertTrue("key store file was not created", f.isFile());

		KeyStore ks = PKIUtils.getKeyStoreInstance(f.getAbsolutePath(), PWD);
		assertEquals(1, ks.size());
		assertTrue("expected a private key entry", ks.isKeyEntry("alias"));
	}

	@Test
	public void testCreateAndLoadJksKeyStore() throws Exception {
		File f = generateKeyStoreFile("store.jks", PKIUtils.JKS_TYPE);
		assertTrue("key store file was not created", f.isFile());

		KeyStore ks = PKIUtils.getKeyStoreInstance(f.getAbsolutePath(), PWD);
		assertEquals(1, ks.size());
		assertTrue("expected a private key entry", ks.isKeyEntry("alias"));
	}

	@Test
	public void testGeneratedCaCertificate() throws Exception {
		assertNotEquals("CA certificate must assert the CA basic constraint", -1,
			caCert.getBasicConstraints());
		caCert.checkValidity();
		assertEquals(caCert.getSubjectX500Principal(), caCert.getIssuerX500Principal());
		caCert.verify(caCert.getPublicKey());		// self-signed
	}

	@Test
	public void testGeneratedUserCertificateIsIssuedByCa() throws Exception {
		assertEquals("end-entity certificate must not assert the CA basic constraint", -1,
			userCert.getBasicConstraints());
		userCert.checkValidity();
		assertEquals(caCert.getSubjectX500Principal(), userCert.getIssuerX500Principal());
		userCert.verify(caCert.getPublicKey());		// signed by the CA

		List<String> eku = userCert.getExtendedKeyUsage();
		assertNotNull("end-entity certificate should specify extended key usage", eku);
		assertTrue("expected clientAuth extended key usage", eku.contains("1.3.6.1.5.5.7.3.2"));
	}

	@Test
	public void testGetCommonName() throws Exception {
		assertEquals("Ghidra Test CA", PKIUtils.getCommonName(caCert));
		assertEquals("Ghidra Test User", PKIUtils.getCommonName(userCert));
	}

	@Test
	public void testGetCommonNameWithoutCommonName() throws Exception {
		assertNull(PKIUtils.getCommonName(noCommonNameCert));
	}

	//==================================================================================
	// Encrypted key stores
	//==================================================================================

	/**
	 * Encryption within a key store applies to the entries it contains and never to the header
	 * which identifies its format, so {@link PKIUtils#detectKeyStoreType(String)} is unaffected by
	 * it.  A PKCS#12 PFX in particular carries its INTEGER version in the clear ahead of any
	 * encrypted content, which is what identifies it.
	 *
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	@Test
	public void testDetectEncryptedKeyStores() throws Exception {
		// key stores holding an encrypted private key
		File p12Key = keyStoreFile("enc-key.p12", PKIUtils.PKCS12_TYPE);
		File jksKey = keyStoreFile("enc-key.jks", PKIUtils.JKS_TYPE);
		assertEquals(PKIUtils.PKCS12_TYPE, PKIUtils.detectKeyStoreType(p12Key.getAbsolutePath()));
		assertEquals(PKIUtils.JKS_TYPE, PKIUtils.detectKeyStoreType(jksKey.getAbsolutePath()));

		// a store whose certificate entries are themselves encrypted is still identified
		File p12Certs = writeCertificateKeyStore("enc-certs.p12", PKIUtils.PKCS12_TYPE, caCert);
		File jksCerts = writeCertificateKeyStore("enc-certs.jks", PKIUtils.JKS_TYPE, caCert);
		assertEquals(PKIUtils.PKCS12_TYPE, PKIUtils.detectKeyStoreType(p12Certs.getAbsolutePath()));
		assertEquals(PKIUtils.JKS_TYPE, PKIUtils.detectKeyStoreType(jksCerts.getAbsolutePath()));
	}

	@Test
	public void testEncryptedKeyStoreRequiresCorrectPassword() throws Exception {
		for (String type : new String[] { PKIUtils.PKCS12_TYPE, PKIUtils.JKS_TYPE }) {
			File f = keyStoreFile("pwd-" + type + ".ks", type);

			// the correct password recovers the encrypted private key
			KeyStore ks = PKIUtils.getKeyStoreInstance(f.getAbsolutePath(), PWD);
			assertNotNull(type + ": expected the private key to be recoverable",
				ks.getKey("alias", PWD));

			try {
				PKIUtils.getKeyStoreInstance(f.getAbsolutePath(), "wrong-password".toCharArray());
				fail(type + ": expected an incorrect key store password to be rejected");
			}
			catch (IOException e) {
				// expected - the store's integrity check fails
			}
		}
	}

	/**
	 * A private key remains encrypted even where the entry holding it can be enumerated without a
	 * password.
	 *
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	@Test
	public void testEncryptedPrivateKeyNotRecoverableWithoutPassword() throws Exception {
		File f = keyStoreFile("keyonly.p12", PKIUtils.PKCS12_TYPE);

		KeyStore ks = PKIUtils.getKeyStoreInstance(f.getAbsolutePath(), null);
		assertEquals("the entry itself remains enumerable", 1, ks.size());
		try {
			ks.getKey("alias", null);
			fail("expected the private key to be unrecoverable without a password");
		}
		catch (Exception e) {
			// expected - the key material is encrypted
		}
	}

	/**
	 * A trust store is loaded without supplying a password, which is only able to yield its
	 * certificates where those entries are not themselves encrypted.  A PKCS#12 store written with
	 * the JDK defaults encrypts them, and so appears empty rather than failing - which is why an
	 * empty result must be reported as a failure to load rather than as an empty trust store.
	 *
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	@Test
	public void testEncryptedCertificateEntriesAreNotReadableWithoutPassword() throws Exception {
		File f = writeCertificateKeyStore("certs-enc.p12", PKIUtils.PKCS12_TYPE, caCert);

		KeyStore withPassword = PKIUtils.getKeyStoreInstance(f.getAbsolutePath(), PWD);
		assertEquals(1, withPassword.size());

		KeyStore withoutPassword = PKIUtils.getKeyStoreInstance(f.getAbsolutePath(), null);
		assertEquals("encrypted certificate entries must not be readable without the password", 0,
			withoutPassword.size());
	}

	/**
	 * JKS holds trusted certificate entries unencrypted, so a JKS trust store is readable without a
	 * password even though the store as a whole was written with one.
	 *
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	@Test
	public void testJksCertificateEntriesAreReadableWithoutPassword() throws Exception {
		File f = writeCertificateKeyStore("certs.jks", PKIUtils.JKS_TYPE, caCert);

		KeyStore ks = PKIUtils.getKeyStoreInstance(f.getAbsolutePath(), null);
		assertEquals(1, ks.size());
		assertEquals(caCert, ks.getCertificate("ca0"));
	}

	/**
	 * The Java default <i>cacerts</i> is a PKCS#12 store whose certificate entries are deliberately
	 * left unencrypted so that it is readable without a password, which is what allows it to be
	 * used as a trust store.
	 *
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	@Test
	public void testUnencryptedCertificateEntriesAreReadableWithoutPassword() throws Exception {
		File cacerts = new File(System.getProperty("java.home"), "lib/security/cacerts");
		if (!cacerts.isFile()) {
			return;		// not present in every JRE layout
		}
		KeyStore ks = PKIUtils.getKeyStoreInstance(cacerts.getAbsolutePath(), null);
		assertTrue("expected the default cacerts to be readable without a password", ks.size() > 0);
	}

	//==================================================================================
	// detectKeyStoreType
	//==================================================================================

	@Test
	public void testDetectJks() throws Exception {
		File f = keyStoreFile("detect.jks", PKIUtils.JKS_TYPE);
		assertEquals(PKIUtils.JKS_TYPE, PKIUtils.detectKeyStoreType(f.getAbsolutePath()));
	}

	@Test
	public void testDetectPkcs12() throws Exception {
		File f = keyStoreFile("detect.p12", PKIUtils.PKCS12_TYPE);
		assertEquals(PKIUtils.PKCS12_TYPE, PKIUtils.detectKeyStoreType(f.getAbsolutePath()));
	}

	/**
	 * A DER encoded certificate begins with the same ASN.1 SEQUENCE tag as a PKCS#12 key store and
	 * must not be mistaken for one - it is not a key store.
	 *
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	@Test
	public void testDetectDerCertificateIsNotAKeyStore() throws Exception {
		File f = writeDer("cert.der", caCert);
		assertNull("a DER certificate is not a key store",
			PKIUtils.detectKeyStoreType(f.getAbsolutePath()));
	}

	/**
	 * A PKCS#12 store large enough to encode its outer SEQUENCE length in DER long form is still
	 * identified, since its INTEGER version element is not then found at a fixed offset.  The store
	 * holding a {@link PKIUtils#KEY_SIZE}-bit key is far larger than the short form's 127-byte limit,
	 * so it is generated for this test rather than depending on the ambient {@code cacerts} (which is
	 * PKCS#12 for a stock JDK, but a JKS file where the platform supplies the trust store).
	 *
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	@Test
	public void testDetectPkcs12WithLongFormLength() throws Exception {
		File f = keyStoreFile("longform.p12", PKIUtils.PKCS12_TYPE);

		// Confirm this fixture actually exercises the long-form path: a SEQUENCE tag (0x30)
		// followed by a length byte whose high bit is set.
		byte[] header = Files.readAllBytes(f.toPath());
		assertEquals("expected a DER SEQUENCE", 0x30, header[0] & 0xFF);
		assertTrue("fixture should use a DER long-form length", (header[1] & 0x80) != 0);

		assertEquals(PKIUtils.PKCS12_TYPE, PKIUtils.detectKeyStoreType(f.getAbsolutePath()));
	}

	@Test
	public void testDetectPemCertificateIsNotAKeyStore() throws Exception {
		File f = writePem("cert.pem", caCert);
		assertNull(PKIUtils.detectKeyStoreType(f.getAbsolutePath()));
	}

	@Test
	public void testDetectNonKeyStoreContent() throws Exception {
		assertNull("text file", PKIUtils.detectKeyStoreType(
			writeText("garbage.txt", "this is not a key store\n").getAbsolutePath()));
		assertNull("empty file",
			PKIUtils.detectKeyStoreType(writeText("empty.bin", "").getAbsolutePath()));
		assertNull("file shorter than any header",
			PKIUtils.detectKeyStoreType(writeText("short.bin", "0").getAbsolutePath()));
		// A SEQUENCE tag alone, with no length or content
		File truncated = file("truncated.der");
		try (FileOutputStream out = new FileOutputStream(truncated)) {
			out.write(new byte[] { 0x30 });
		}
		assertNull("truncated DER", PKIUtils.detectKeyStoreType(truncated.getAbsolutePath()));
	}

	@Test(expected = IOException.class)
	public void testDetectMissingFile() throws Exception {
		PKIUtils.detectKeyStoreType(file("does-not-exist").getAbsolutePath());
	}

	//==================================================================================
	// exportX509Certificates / loadX509PemCertificates
	//==================================================================================

	@Test
	public void testPemExportImportRoundTrip() throws Exception {
		File f = writePem("bundle.pem", userCert, caCert);

		List<X509Certificate> certs = PKIUtils.loadX509PemCertificates(f);
		assertEquals(2, certs.size());
		assertEquals(userCert, certs.get(0));
		assertEquals(caCert, certs.get(1));
	}

	@Test
	public void testLoadPemStrictRejectsMalformedBlock() throws Exception {
		File f = writePem("bundle.pem", caCert);
		String contents = Files.readString(f.toPath()) +
			"-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n";
		File mixed = writeText("mixed.pem", contents);

		try {
			PKIUtils.loadX509PemCertificates(mixed);
			fail("expected a malformed PEM block to be rejected");
		}
		catch (CertificateException e) {
			// expected - a file supplied for validation must report its defects
		}
	}

	@Test
	public void testLoadPemStrictRejectsNonCertificateBlock() throws Exception {
		File f = writeText("key.pem",
			"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n");
		try {
			PKIUtils.loadX509PemCertificates(f);
			fail("expected a non-certificate PEM block to be rejected");
		}
		catch (CertificateException e) {
			// expected
		}
	}

	@Test
	public void testLoadPemTolerantSkipsMalformedBlock() throws Exception {
		File f = writePem("bundle.pem", userCert, caCert);
		String contents = Files.readString(f.toPath()) +
			"-----BEGIN CERTIFICATE-----\nnot valid base64 !!!\n-----END CERTIFICATE-----\n";
		File mixed = writeText("mixed.pem", contents);

		List<String> problems = new ArrayList<>();
		List<X509Certificate> certs = PKIUtils.loadX509PemCertificates(mixed, problems::add);

		assertEquals("valid certificates must still be read", 2, certs.size());
		assertEquals("the unusable block must be reported", 1, problems.size());
		assertTrue("report should identify the block: " + problems.get(0),
			problems.get(0).contains("PEM block"));
	}

	@Test
	public void testLoadPemTolerantSkipsNonCertificateBlock() throws Exception {
		File f = writePem("bundle.pem", caCert);
		String contents = Files.readString(f.toPath()) +
			"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n";
		File mixed = writeText("mixed.pem", contents);

		List<String> problems = new ArrayList<>();
		List<X509Certificate> certs = PKIUtils.loadX509PemCertificates(mixed, problems::add);

		assertEquals(1, certs.size());
		assertEquals(1, problems.size());
	}

	@Test
	public void testLoadPemEmptyFile() throws Exception {
		File f = writeText("empty.pem", "");
		assertTrue(PKIUtils.loadX509PemCertificates(f).isEmpty());
	}

	//==================================================================================
	// loadCertificateStore / loadX509CertificateStore
	//==================================================================================

	@Test
	public void testLoadCertificateStoreFromPem() throws Exception {
		File f = writePem("bundle.pem", userCert, caCert);

		KeyStore ks = PKIUtils.loadCertificateStore(f.getAbsolutePath());
		assertEquals(2, ks.size());
		assertTrue("certificates should be trusted entries", containsCertificate(ks, caCert));
		assertTrue(containsCertificate(ks, userCert));
	}

	@Test
	public void testLoadCertificateStoreFromDer() throws Exception {
		File f = writeDer("cert.der", caCert);

		KeyStore ks = PKIUtils.loadCertificateStore(f.getAbsolutePath());
		assertEquals(1, ks.size());
		assertTrue(containsCertificate(ks, caCert));
	}

	@Test
	public void testLoadX509CertificateStoreCountsCertificates() throws Exception {
		File f = writePem("bundle.pem", userCert, caCert);

		List<X509Certificate> consumed = new ArrayList<>();
		int count = PKIUtils.loadX509CertificateStore(f.getAbsolutePath(), consumed::add);
		assertEquals(2, count);
		assertEquals(2, consumed.size());
	}

	/**
	 * Certificates sharing a common name must not displace one another within the loaded store,
	 * which would silently reduce the set of trusted authorities.
	 *
	 * @throws Exception if an unexpected keystore or cryptographic error occurs
	 */
	@Test
	public void testLoadCertificateStoreRetainsCertificatesWithDuplicateCommonName()
			throws Exception {
		assertNotEquals("expected two distinct certificates", caCert, renewedCaCert);

		File f = writePem("dupcn.pem", caCert, renewedCaCert);
		KeyStore ks = PKIUtils.loadCertificateStore(f.getAbsolutePath());

		assertEquals("both certificates must be retained", 2, ks.size());
		assertTrue(containsCertificate(ks, caCert));
		assertTrue(containsCertificate(ks, renewedCaCert));
	}

	//==================================================================================
	// getTrustManager
	//==================================================================================

	@Test
	public void testTrustManagerAcceptsCertificateIssuedByLoadedAuthority() throws Exception {
		File caFile = writePem("ca.pem", caCert);

		X509TrustManager trustManager = PKIUtils.getTrustManager(caFile);
		X509Certificate[] issuers = trustManager.getAcceptedIssuers();
		assertEquals(1, issuers.length);
		assertEquals(caCert, issuers[0]);

		// the certificate the CA issued must be accepted
		trustManager.checkClientTrusted(new X509Certificate[] { userCert, caCert },
			PKIUtils.RSA_TYPE);
	}

	@Test
	public void testTrustManagerRejectsCertificateFromUnknownAuthority() throws Exception {
		File caFile = writePem("otherca.pem", otherCaCert);

		X509TrustManager trustManager = PKIUtils.getTrustManager(caFile);
		try {
			trustManager.checkClientTrusted(new X509Certificate[] { userCert }, PKIUtils.RSA_TYPE);
			fail("expected a certificate from an unknown authority to be rejected");
		}
		catch (CertificateException e) {
			// expected
		}
	}

	@Test(expected = IOException.class)
	public void testTrustManagerMissingFile() throws Exception {
		PKIUtils.getTrustManager(file("does-not-exist.pem"));
	}

	//==================================================================================

	private static boolean containsCertificate(KeyStore ks, X509Certificate cert)
			throws KeyStoreException {
		for (String alias : Collections.list(ks.aliases())) {
			if (cert.equals(ks.getCertificate(alias))) {
				return true;
			}
		}
		return false;
	}
}
