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
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import ghidra.util.Msg;

/**
 * Loads a trust {@link KeyStore} from a CA certificates file, which may be a Java key store
 * (JKS or PKCS12) or a certificate file (one or more PEM encoded certificates, or a DER encoded
 * certificate).
 * <p>
 * The form of the file is determined from its content rather than by attempting each in turn, so
 * that a failure to load can report why it failed instead of only that every attempt was
 * unsuccessful.
 */
final class FlexibleTrustStoreLoader {

	private static final int DER_SEQUENCE_TAG = 0x30;

	private FlexibleTrustStoreLoader() {
		// no construct - static utility
	}

	/**
	 * Load a trust KeyStore from a Java key store (JKS, PKCS12) or a certificate file
	 * (PEM or DER).
	 *
	 * @param cacertsPath path to CA certificates file
	 * @return loaded certificates as keystore
	 * @throws KeyStoreException if unable to load cacerts file
	 * @throws FileNotFoundException cacerts file not found
	 */
	public static KeyStore getTrustStore(String cacertsPath)
			throws FileNotFoundException, KeyStoreException {

		File cacertsFile = new File(cacertsPath);
		if (!cacertsFile.isFile()) {
			throw new FileNotFoundException("CA Certificates file not found: " + cacertsPath);
		}

		String keyStoreType = detectKeyStoreType(cacertsFile);
		if (keyStoreType != null) {
			Exception failure;
			try {
				// No password is supplied: trusted certificate entries are held unencrypted
				// within a JKS key store, and within a PKCS12 key store written for this purpose
				// (the Java default 'cacerts' among them), so they are readable without one.  A
				// key store which does not hold its certificates that way yields no entries,
				// which is reported as a failure to load rather than as an empty trust store.
				KeyStore keyStore =
					PKIUtils.getKeyStoreInstance(cacertsFile.getAbsolutePath(), null);
				if (keyStore.size() != 0) {
					return keyStore;
				}
				failure = new KeyStoreException(
					"key store contains no certificate entries; it may be password protected");
			}
			catch (IOException | GeneralSecurityException e) {
				failure = e;
			}
			// A PKCS12 key store and a DER encoded certificate both begin with the same byte, so
			// a file which is detected as PKCS12 but does not load as one may simply be a
			// certificate; any other type which fails to load is a definite failure.
			if (!PKIUtils.PKCS12_TYPE.equals(keyStoreType)) {
				throw new KeyStoreException(
					"Failed to load " + keyStoreType + " trust store: " + cacertsPath, failure);
			}
		}

		try {
			List<String> unusableBlocks = new ArrayList<>();
			List<X509Certificate> certs = loadCertificates(cacertsFile, unusableBlocks);
			if (certs.isEmpty()) {
				// Report why each block was rejected, since none of them produced a certificate
				throw new CertificateException(unusableBlocks.isEmpty()
						? "file does not contain a certificate"
						: "file contains no usable certificate: " +
							String.join("; ", unusableBlocks));
			}
			return createTrustStore(certs);
		}
		catch (IOException | GeneralSecurityException e) {
			throw new KeyStoreException("Failed to load CA certificates file: " + cacertsPath, e);
		}
	}

	/**
	 * Determine the Java key store type of a file from its content.
	 * @param file CA certificates file
	 * @return the key store type, or null if the file is not a Java key store
	 * @throws KeyStoreException if the file cannot be read
	 */
	private static String detectKeyStoreType(File file) throws KeyStoreException {
		try {
			return PKIUtils.detectKeyStoreType(file.getAbsolutePath());
		}
		catch (IOException e) {
			throw new KeyStoreException("Failed to read CA certificates file: " + file, e);
		}
	}

	/**
	 * Read the certificates contained within a certificate file.
	 * <p>
	 * A PEM block which cannot be used is reported and skipped rather than abandoning the file:
	 * this establishes the certificate authorities every SSL connection depends upon, so
	 * discarding all of them on account of one defective block would be the greater failure.
	 *
	 * @param file certificate file
	 * @param unusableBlocks collects a description of each PEM block which was skipped
	 * @return the certificates read, which may be empty
	 * @throws IOException if the file cannot be read
	 * @throws CertificateException if the file cannot be parsed
	 */
	private static List<X509Certificate> loadCertificates(File file, List<String> unusableBlocks)
			throws IOException, CertificateException {

		if (isDerEncoded(file)) {
			return loadDerCertificates(file);
		}

		List<X509Certificate> certs = PKIUtils.loadX509PemCertificates(file, unusableBlocks::add);
		for (String unusable : unusableBlocks) {
			Msg.warn(FlexibleTrustStoreLoader.class,
				"Ignored unusable certificate within " + file.getAbsolutePath() + ": " + unusable);
		}
		return certs;
	}

	/**
	 * @param file certificate file
	 * @return true if the file appears to be DER encoded
	 * @throws IOException if the file cannot be read
	 */
	private static boolean isDerEncoded(File file) throws IOException {
		try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
			int c;
			while ((c = in.read()) != -1) {
				if (!Character.isWhitespace(c)) {
					return c == DER_SEQUENCE_TAG;
				}
			}
		}
		return false;		// empty file - handled as an absence of certificates
	}

	/**
	 * Read one or more DER encoded certificates from a file.
	 * @param file certificate file
	 * @return the X509 certificates read
	 * @throws IOException if the file cannot be read
	 * @throws CertificateException if the file cannot be parsed
	 */
	private static List<X509Certificate> loadDerCertificates(File file)
			throws IOException, CertificateException {

		List<X509Certificate> certs = new ArrayList<>();
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
			for (Certificate cert : cf.generateCertificates(in)) {
				if (cert instanceof X509Certificate x509Cert) {
					certs.add(x509Cert);
				}
			}
		}
		return certs;
	}

	/**
	 * Establish an in-memory trust store containing the specified certificates.
	 * @param certs certificates to be trusted
	 * @return the trust store
	 * @throws KeyStoreException if the trust store cannot be created or populated
	 * @throws IOException if the empty trust store cannot be initialized
	 * @throws NoSuchAlgorithmException if the trust store integrity algorithm is unavailable
	 * @throws CertificateException if the empty trust store's certificate data cannot be processed
	 */
	private static KeyStore createTrustStore(List<X509Certificate> certs)
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		ks.load(null, null);
		int i = 0;
		for (X509Certificate cert : certs) {
			ks.setCertificateEntry("cert-" + (i++), cert);
		}
		return ks;
	}

}
