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
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import ghidra.util.Msg;
import ghidra.util.NumericUtilities;

/**
 * Builds a trust {@link KeyStore} backed by the host Linux (and BSD variants) operating system's 
 * known CA trust-store locations. 
 *
 * <p>Rationale: Java ships no native "OS trust store" KeyStore provider on
 * Linux/BSD (unlike "Windows-ROOT" on Windows or "KeychainStore" on macOS).
 * Nearly every distro instead maintains one or more PEM bundle files (and/or
 * a directory of individual PEM certs) kept in sync with the system's trust
 * configuration by tooling such as update-ca-certificates, update-ca-trust,
 * or p11-kit. This class scans the well-known locations for those bundles,
 * parses every certificate it finds, de-duplicates by fingerprint, and loads
 * the result into an in-memory KeyStore that is handed to a
 * TrustManagerFactory.
 *
 * <p>Desktop environments (GNOME, KDE, XFCE, Cinnamon, etc.) don't keep a
 * separate trust store for TLS -- they consume the same system bundle
 * (often via p11-kit / NSS, which is itself synced from the paths below), so
 * no desktop-manager-specific handling is required beyond this.
 *
 * <p><b>Only the trust configuration the OS has actually put into effect is used.</b> The
 * locations scanned are those which the OS tooling <i>produces</i> -- the extracted bundles of
 * {@link #BUNDLE_FILES} and the enabled-certificate directories of {@link #BUNDLE_DIRS} -- and
 * never the source/anchor directories which feed that tooling. Those source directories retain
 * certificates which an administrator has since disabled: Debian and Ubuntu disable a CA by
 * prefixing it with {@code !} in {@code /etc/ca-certificates.conf} (the file itself remaining
 * under {@code /usr/share/ca-certificates}), and RHEL and Fedora distrust one through
 * {@code /etc/pki/ca-trust/source/blocklist} while it may still sit in
 * {@code source/anchors}. Reading a source directory would therefore re-trust exactly those
 * authorities the administrator removed, so it is not done.
 *
 * <p>Known limitations:
 * <ul>
 *   <li>Requires read access to the relevant system paths (usually
 *       world-readable, but not guaranteed in hardened/minimal images).</li>
 *   <li>Minimal container images (e.g. distroless, scratch) may not have any
 *       CA bundle installed at all -- no OS trust store is produced in that case
 *       and the caller falls back to the Java default trust store.</li>
 *   <li>Distros that route trust exclusively through a PKCS#11/NSS token
 *       rather than exporting a PEM bundle are not covered; nearly all
 *       mainstream distros do export a PEM bundle as of this writing.</li>
 * </ul>
 */
public final class UnixSystemTrustKeyStoreUtil {
	
	private static final String UNIX_DEFAULT_CA_BUNDLE_PATH_PROPERTY = "ghidra.unix.default.cacerts";

	/** Known single-file CA bundle locations, checked in this order. */
	private static final List<String> BUNDLE_FILES = List.of(
		// Debian / Ubuntu / Linux Mint / Alpine / Gentoo (app-misc/ca-certificates)
		"/etc/ssl/certs/ca-certificates.crt",
		// RHEL / CentOS / Fedora (post "update-ca-trust extract")
		"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
		"/etc/pki/tls/certs/ca-bundle.crt",
		// openSUSE / SLES
		"/etc/ssl/ca-bundle.pem",
		"/var/lib/ca-certificates/ca-bundle.pem",
		// Arch Linux
		"/etc/ca-certificates/extracted/tls-ca-bundle.pem",
		// Generic OpenSSL default location (also used by several distros/BSDs)
		"/etc/ssl/cert.pem",
		// FreeBSD (security/ca_root_nss)
		"/usr/local/share/certs/ca-root-nss.crt",
		"/usr/local/etc/ssl/cert.pem"
	// Note: OpenBSD's base-system bundle is also /etc/ssl/cert.pem,
	// already covered above.
	);

	/**
	 * Known directories of individual PEM certs, scanned only when no bundle file was found.
	 * <p>
	 * These hold the <i>enabled</i> certificates as published by the OS trust tooling.  Source and
	 * anchor directories which feed that tooling ({@code /usr/share/ca-certificates} and
	 * {@code /etc/pki/ca-trust/source/anchors}) are deliberately absent: they also retain
	 * certificates the administrator has disabled or blocklisted, so reading them would re-trust
	 * authorities the OS no longer trusts.
	 */
	private static final List<String> BUNDLE_DIRS = List.of(
		"/etc/ssl/certs",                    // Debian/Ubuntu/Alpine/Gentoo/OpenBSD (hash-named symlinks)
		"/usr/local/share/certs"             // FreeBSD
	);

	private UnixSystemTrustKeyStoreUtil() {
	}

	/**
	 * Scans the known OS trust-store locations and loads every distinct, valid CA certificate
	 * found into a new in-memory KeyStore.
	 * <p>
	 * The locations are consulted in a defined order of precedence rather than being combined:
	 * <ol>
	 * <li>the <b>first</b> of {@link #BUNDLE_FILES} which yields a CA certificate is used, and no
	 * further bundle is read.  The bundles are not merged because a stale bundle left behind at
	 * another location would otherwise re-introduce certificate authorities which have since been
	 * removed from the one the OS currently maintains;</li>
	 * <li>{@link #BUNDLE_DIRS} is scanned only if no bundle file yielded anything, covering the
	 * distros which publish individual certificates rather than a bundle;</li>
	 * <li>a location given by the <i>ghidra.unix.default.cacerts</i> property is always applied in
	 * addition to the above, since it is an explicit administrative choice.</li>
	 * </ol>
	 *
	 * @return a {@code PKCS12} KeyStore containing one {@code setCertificateEntry}
	 *         per distinct CA certificate discovered (aliased {@code "system-ca-0"},
	 *         {@code "system-ca-1"}, ...); null returned if no CA certs were found.
	 * @throws KeyStoreException if the in-memory KeyStore cannot be created or
	 *         populated (e.g. the {@code "PKCS12"} KeyStore type is unavailable)
	 * @throws IOException if an I/O error occurs while initializing the empty
	 *         KeyStore
	 * @throws NoSuchAlgorithmException if the platform has no provider for the
	 *         {@code "X.509"} CertificateFactory or the KeyStore's integrity
	 *         algorithm
	 * @throws CertificateException if the KeyStore's own load step fails to
	 *         process its (empty) certificate data
	 */
	static KeyStore loadSystemCaKeyStore()
			throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(null, null);

		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		Set<String> seenFingerprints = new HashSet<>();
		AtomicInteger aliasCounter = new AtomicInteger();

		// Use the first bundle which yields certificates; see precedence above
		for (String path : BUNDLE_FILES) {
			loadCaKeyStorePath(path, keyStore, certFactory, seenFingerprints, aliasCounter);
			if (aliasCounter.get() != 0) {
				break;
			}
		}

		if (aliasCounter.get() == 0) {
			loadCaKeyStorePaths(BUNDLE_DIRS, keyStore, certFactory, seenFingerprints, aliasCounter);
		}

		String optionalCaBundlePath = System.getProperty(UNIX_DEFAULT_CA_BUNDLE_PATH_PROPERTY);
		if (optionalCaBundlePath != null && !optionalCaBundlePath.isBlank()) {
			loadCaKeyStorePath(optionalCaBundlePath, keyStore, certFactory, seenFingerprints,
				aliasCounter);
		}

		if (aliasCounter.get() == 0) {
			Msg.error(UnixSystemTrustKeyStoreUtil.class, """
					No readable OS CA certificate bundle found among known Linux/BSD locations.
					The process may lack read permission, the ca-certificates package may not
					be installed (common in minimal container images), or this OS distro's layout
					isn't currently supported.
					""");
			return null;
		}
		return keyStore;
	}
	
	private static void loadCaKeyStorePaths(List<String> caStorePaths, KeyStore keyStore, CertificateFactory certFactory, Set<String> seenFingerprints, AtomicInteger aliasCounter) {
		for (String path : caStorePaths) {
			loadCaKeyStorePath(path, keyStore, certFactory, seenFingerprints, aliasCounter);
		}
	}

	/**
	 * Load the CA certificates held by a single location, which may be either a bundle file or a
	 * directory of individual certificate files.
	 *
	 * @param path location to be loaded
	 * @param keyStore trust store being populated
	 * @param certFactory X.509 certificate factory
	 * @param seenFingerprints fingerprints of the certificates already added, for de-duplication
	 * @param aliasCounter running count of certificates added, used to alias each entry
	 * @return the number of certificates loaded from this location
	 */
	private static int loadCaKeyStorePath(String path, KeyStore keyStore,
			CertificateFactory certFactory, Set<String> seenFingerprints,
			AtomicInteger aliasCounter) {

		File loc = new File(path);
		int loadedCertCount = 0;

		if (!loc.isDirectory()) {
			// Load individual CA store file
			loadedCertCount = loadFile(loc, keyStore, certFactory, seenFingerprints, aliasCounter);
		}
		else {
			// Load directory of CA store files
			File[] files = loc.listFiles();
			if (files == null) {
				return 0;
			}
			for (File f : files) { // NOTE: sub-directories will not be loaded
				loadedCertCount += loadFile(f, keyStore, certFactory, seenFingerprints, aliasCounter);
			}
		}

		if (loadedCertCount != 0) {
			Msg.info(UnixSystemTrustKeyStoreUtil.class, "Loaded " + loadedCertCount + " trusted CA certificate(s) from " + loc);
		}
		return loadedCertCount;
	}

	private static int loadFile(File f, KeyStore keyStore, CertificateFactory certFactory,
			Set<String> seenFingerprints, AtomicInteger aliasCounter) {
		if (!f.isFile() || !f.canRead() || f.length() == 0) {
			return 0;
		}
		int loadedCertCount = 0;
		try (InputStream in = new BufferedInputStream(new FileInputStream(f))) {
			// CertificateFactory.generateCertificates handles a stream containing
			// multiple concatenated PEM certificates (the normal "bundle" format).
			for (Certificate cert : certFactory.generateCertificates(in)) {
				if (!(cert instanceof X509Certificate)) {
					continue;
				}
				X509Certificate x509 = (X509Certificate) cert;
				if (!isCertificateAuthority(x509)) {
					// Some scanned locations (notably /etc/ssl/certs) are general-purpose
					// OpenSSL cert directories, not exclusively CA bundles -- skip anything
					// that isn't actually marked as a CA so we never trust a stray leaf/server
					// certificate as if it were a trust anchor.
					continue;
				}
				if (addIfNew(keyStore, x509, seenFingerprints, aliasCounter.get())) {
					aliasCounter.incrementAndGet();
					++loadedCertCount;
				}
			}
		}
		catch (CertificateException | IOException | KeyStoreException
				| NoSuchAlgorithmException e) {
			// Not every file under e.g. /etc/ssl/certs or /usr/share/ca-certificates is a
			// parseable certificate (broken symlinks, READMEs, etc.) -- skip and continue.
		}
		return loadedCertCount;
	}

	/**
	 * Returns true if the certificate's BasicConstraints extension marks it as a
	 * CA (cA=true). Used to filter out non-CA (leaf/server/user) certificates that
	 * may be co-located in scanned directories -- not every location in
	 * BUNDLE_DIRS is exclusively reserved for CA certs by every distro or admin
	 * convention (e.g. /etc/ssl/certs is also OpenSSL's general-purpose CApath).
	 */
	private static boolean isCertificateAuthority(X509Certificate cert) {
		// getBasicConstraints() returns the CA path-length constraint (>= 0, or
		// Integer.MAX_VALUE if unlimited) when cA=true, and -1 otherwise.
		return cert.getBasicConstraints() != -1;
	}

	private static boolean addIfNew(KeyStore keyStore, X509Certificate cert,
			Set<String> seenFingerprints, int aliasCounter)
			throws KeyStoreException, CertificateEncodingException, NoSuchAlgorithmException {
		String fingerprint = sha256Fingerprint(cert);
		if (!seenFingerprints.add(fingerprint)) {
			return false; // duplicate cert, already present
		}
		keyStore.setCertificateEntry("system-ca-" + aliasCounter, cert);
		return true;
	}

	private static String sha256Fingerprint(X509Certificate cert)
			throws CertificateEncodingException, NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(cert.getEncoded());
		return NumericUtilities.convertBytesToString(digest);
	}

}
