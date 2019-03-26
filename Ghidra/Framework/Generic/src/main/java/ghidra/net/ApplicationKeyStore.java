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
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;
import javax.swing.filechooser.FileNameExtensionFilter;

import ghidra.util.Msg;

/**
 * <code>ApplicationKeyStore</code> provides the ability to read X.509 certificates and 
 * keystores in various formats. Certificate files (e.g., cacerts) may be in a standard
 * X.509 form (*.pem, *.crt, *.cer, *.der) or Java JKS (*.jks) form, while keystores 
 * for client/server may be in a PKCS12 form (*.p12, *.pks, *.pfx) or Java JKS (*.jks) form.
 */
class ApplicationKeyStore {

	static final String[] PKCS_FILE_EXTENSIONS = new String[] { "p12", "pks", "pfx" };

	private static final FileNameExtensionFilter PKCS_FILENAME_FILTER =
		new FileNameExtensionFilter("PKCS Key File", PKCS_FILE_EXTENSIONS);

	private ApplicationKeyStore() {
		// no instantiation - static methods only
	}

	/**
	 * Load the specified X.509 certificate authority store in a standard
	 * X.509 form (*.pem, *.crt, *.cer, *.der) or Java JKS (*.jks) form.
	 * @param cacertsPath certificate store file path
	 * @return KeyStore containing ingested certificates
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	static KeyStore getCertificateStoreInstance(String cacertsPath)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

		int certCount = 0;

		KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
		store.load(null);

		InputStream fis = new FileInputStream(cacertsPath);
		BufferedInputStream bis = new BufferedInputStream(fis);

		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			while (bis.available() > 0) {
				try {
					Certificate cert = cf.generateCertificate(bis);
					if (cert instanceof X509Certificate) {
						X509Certificate x509Cert = (X509Certificate) cert;
						String name = getCommonName(x509Cert.getSubjectDN());
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
			return getKeyStoreInstance(cacertsPath, null);
		}
		return store;
	}

	/**
	 * Attempt to load a client/server keystore in a PKCS12 form (*.p12, *.pks, *.pfx) or 
	 * Java JKS (*.jks) form.
	 * @param path keystore file path
	 * @param pwd keystore password
	 * @return keystore instance
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	static KeyStore getKeyStoreInstance(String keystorePath, char[] pwd)
			throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {

		File keystoreFile = new File(keystorePath);
		boolean isPKCS12 = PKCS_FILENAME_FILTER.accept(keystoreFile);
		String type = isPKCS12 ? "PKCS12" : "JKS"; // JKS assumed if not PKCS
		KeyStore ks = KeyStore.getInstance(type);

		InputStream fis = new FileInputStream(keystorePath);
		BufferedInputStream bis = new BufferedInputStream(fis);
		try {
			ks.load(bis, pwd);
		}
		finally {
			bis.close();
		}
		return ks;
	}

	/**
	 * Extract Common Name (CN) from specified principal subject Distinguished Name (DN)
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
					Msg.warn(ApplicationKeyStore.class, "Ignore unrecognized certificate: alias=" +
						alias + ", type=" + certificate.getType());
				}
			}
		}
		catch (KeyStoreException e) {
			Msg.error(ApplicationKeyStore.class, "KeyStore failure", e);
		}
	}

	/**
	 * Log all X509 certificates contained within array
	 * @param x509Certs array of certificates
	 */
	static void logCerts(X509Certificate[] x509Certs) {
		for (X509Certificate x509Cert : x509Certs) {
			logCert(null, x509Cert);
		}
	}

	/**
	 * Log specified X509 certificate details
	 * @param alias certificate alias or null if not applicable
	 * @param x509Cert X509 certificate
	 */
	static void logCert(String alias, X509Certificate x509Cert) {

		X500Principal subj = x509Cert.getSubjectX500Principal();
		X500Principal issuer = x509Cert.getIssuerX500Principal();

		Date now = new Date();

		String label = alias != null ? (alias + ": ") : "";
		if (now.compareTo(x509Cert.getNotAfter()) > 0) {
			Msg.warn(ApplicationKeyStore.class,
				"   " + label + getCommonName(subj) + ", issued by " + getCommonName(issuer) +
					", S/N " + x509Cert.getSerialNumber().toString(16) + ", expired " +
					x509Cert.getNotAfter() + " **EXPIRED**");
		}
		else {
			Msg.info(ApplicationKeyStore.class,
				"   " + label + getCommonName(subj) + ", issued by " + getCommonName(issuer) +
					", S/N " + x509Cert.getSerialNumber().toString(16) + ", expires " +
					x509Cert.getNotAfter());
		}
	}

}
