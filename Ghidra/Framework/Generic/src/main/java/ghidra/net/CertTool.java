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

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.*;
import org.bouncycastle.openssl.jcajce.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.IPAddress;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import utilities.util.FileUtilities;

public class CertTool implements GhidraLaunchable {

	static {
		Security.addProvider(new BouncyCastleProvider());
	}

	private static final String INVOCATION_NAME_PROPERTY = "CertTool.invocation";
	private static int MIN_PWD_LENGTH = 4;

	// Provided for testing only
//	public static void main(String[] args) throws IOException {
//		CertTool certTool = new CertTool();
//		certTool.launch(new GhidraApplicationLayout(), args);
//	}

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) {

		// Perform static initializations if not already initialized
		// Some tests invoke main method directly which have already initialized
		// Application
		if (!Application.isInitialized()) {
			ApplicationConfiguration configuration = new ApplicationConfiguration();
			configuration.setInitializeLogging(false);
			Application.initializeApplication(layout, configuration);
		}

		int rc = execute(args);
		System.exit(rc);
	}

	private int execute(String[] args) {
		if (args.length < 1) {
			displayUsage(null);
			return -1;
		}

		String command = args[0];
		try {
			if ("request".equals(command)) {
				return handleRequestCommand(args);
			}
			if ("pkcs12".equals(command)) {
				return handlePkcs12Command(args);
			}
			displayUsage("Unknown command: " + command);
		}
		catch (Exception e) {
			System.err.println("Error executing command: " + e.getMessage());
		}
		return -1;
	}

	private String getNextArg(String[] args, String optionName, int index, String currentValue)
			throws IllegalArgumentException {
		if (currentValue != null) {
			throw new IllegalArgumentException("Duplicate option " + optionName);
		}
		if (index >= args.length) {
			throw new IllegalArgumentException("Missing " + optionName + " argument");
		}
		return args[index];
	}

	private int handleRequestCommand(String[] args) throws Exception {
		String keyFile = null;
		try {
			for (int i = 1; i < args.length; i++) {
				if ("-outkey".equals(args[i])) {
					keyFile = getNextArg(args, "-outkey", ++i, keyFile);
				}
				else {
					throw new IllegalArgumentException("Unexpected argument: " + args[i]);
				}
			}
		}
		catch (IllegalArgumentException e) {
			System.err.println(e.getMessage());
			return -1;
		}

		if (keyFile == null) {
			displayUsage("Missing -outkey option");
			return -1;
		}

		if (!checkOverwrite(new File(keyFile))) {
			return -1;
		}

		// Generate key pair
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(PKIUtils.RSA_TYPE, "BC");
		keyGen.initialize(PKIUtils.KEY_SIZE);
		KeyPair keyPair = keyGen.generateKeyPair();

		// Prompt for DN information
		Map<String, String> dnMap = promptForDnInfo();

		// Save private key
		if (!savePrivateKey(keyFile, keyPair.getPrivate())) {
			System.err.println("Request generation failed!");
			return -1;
		}

		// Output private key in encrypted PEM format
		System.out.println("Private key saved to: " + keyFile);

		// Define the Distinguished Name (DN) using X500Name
		X500Name subject = getDN(dnMap);
		X500Principal principal = new X500Principal(subject.getEncoded());
		String dn = principal.getName(); // CN first

		System.out.println("Generating certificate request for: " + dn);

		// Create the JcaPKCS10CertificationRequestBuilder
		JcaPKCS10CertificationRequestBuilder csrBuilder =
			new JcaPKCS10CertificationRequestBuilder(subject,
				keyPair.getPublic());

		// Add Extensions to the CSR
		ExtensionsGenerator extGen = new ExtensionsGenerator();

		KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
		extGen.addExtension(Extension.keyUsage, true, // Is Critical? Yes, standard practice for Key Usage
			keyUsage);

		// Add extended usage to include client and server authentication
		KeyPurposeId[] usages = new KeyPurposeId[] { KeyPurposeId.id_kp_serverAuth, // TLS Web Server Authentication
			KeyPurposeId.id_kp_clientAuth // TLS Web Client Authentication
		};
		ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(usages);
		extGen.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);

		// Add Subject Alternative Name(s) (SANs) ---
		GeneralNames subjectAltNames = getSubjectAlternativeNames(dnMap);
		if (subjectAltNames != null) {
			extGen.addExtension(Extension.subjectAlternativeName, false, // Is Critical? No, typically false for SAN
				subjectAltNames);
		}

		csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
			extGen.generate());

		// Create a Content Signer using the private key
		ContentSigner signer =
			new JcaContentSignerBuilder(PKIUtils.SIGNING_ALGORITHM).setProvider("BC")
					.build(keyPair.getPrivate());

		// Build the PKCS#10 CSR object
		PKCS10CertificationRequest csr = csrBuilder.build(signer);

		// Convert the CSR to PEM format for distribution
		StringWriter stringWriter = new StringWriter();
		try (PemWriter pemWriter = new PemWriter(stringWriter)) {
			pemWriter.writeObject(new PemObject("CERTIFICATE REQUEST", csr.getEncoded()));
		}

		// Print the final CSR
		System.out.println("\n" + stringWriter.toString());

		System.out.println("""
				The above request data may be submitted to your certificate
				authority to obtain a signed certificate.  Once you obtain
				your signed certificate it may be combined with the key file,
				that was generated and stored above, into a pkcs12 (*.p12)
				keystore using the following command using appropriate
				filenames (omit file-extension for -out file):
				""");

		String invocationName = System.getProperty(INVOCATION_NAME_PROPERTY);
		System.out.println(
			"   " + invocationName + " pkcs12 -inkey server.key -cert server.crt -out server\n");

		return 0;
	}

	private int handlePkcs12Command(String[] args) throws Exception {
		boolean selfSigned = false;
		String keyFile = null;
		String certFile = null;
		String outFile = null;
		String caFile = null;
		try {
			for (int i = 1; i < args.length; i++) {
				if ("-self-signed".equals(args[i])) {
					selfSigned = true;
				}
				else if ("-inkey".equals(args[i])) {
					keyFile = getNextArg(args, "-inkey", ++i, keyFile);
				}
				else if ("-cert".equals(args[i])) {
					certFile = getNextArg(args, "-cert", ++i, certFile);
				}
				else if ("-out".equals(args[i])) {
					outFile = getNextArg(args, "-out", ++i, outFile);
				}
				else if ("-cachain".equals(args[i])) {
					caFile = getNextArg(args, "-cachain", ++i, caFile);
				}
				else {
					throw new IllegalArgumentException("Unexpected argument: " + args[i]);
				}
			}
		}
		catch (IllegalArgumentException e) {
			System.err.println(e.getMessage());
			return -1;
		}

		if (selfSigned && keyFile == null && certFile == null && outFile != null &&
			caFile == null) {
			return handleSelfSignedCommand(outFile);
		}
		if (!selfSigned && keyFile != null && certFile != null && outFile != null) {
			return handlePkcs12StoreCommand(keyFile, certFile, caFile, outFile);
		}
		displayUsage(
			"Invalid pkcs12 command. Use -self-signed or provide -inkey/-cert/-out options.");
		return -1;
	}

	private int handleSelfSignedCommand(String outFile) throws Exception {

		if (endsWithKnownExtension(outFile)) {
			return -1;
		}

		File certFile = new File(outFile + ".crt");
		File pkcs12File = new File(outFile + ".p12");

		if (!checkOverwrite(certFile) || !checkOverwrite(pkcs12File)) {
			return -1;
		}

		// Prompt for DN information
		Map<String, String> dnMap = promptForDnInfo();

		// Get the Distinguished Name (DN) using X500Name
		X500Name subject = getDN(dnMap);
		X500Principal principal = new X500Principal(subject.getEncoded());
		String dn = principal.getName(); // CN first

		System.out.println("Generating self-signed certificate for: " + dn);

		char[] pwd = promptForNewPassword("Enter new keystore password:");
		if (pwd == null) {
			return -1;
		}
		try {
			String alias = dnMap.get("CN");
			KeyStore keyStore =
				PKIUtils.createKeyStore(alias, dn, 365, null, false, pkcs12File, "PKCS12",
					getSubjectAlternativeNameList(dnMap), pwd);

			System.out.println("Self-signed keystore generated: " + pkcs12File);

			Certificate certificate = keyStore.getCertificate(alias);
			PKIUtils.exportX509Certificates(new Certificate[] { certificate }, certFile);

			System.out.println("Self-signed certificate generated: " + certFile);
		}
		finally {
			Arrays.fill(pwd, (char) 0);
		}
		return 0;
	}

	private int handlePkcs12StoreCommand(String keyFile, String certFile, String caFile,
			String outFile)
			throws Exception {

		File pkcs12File;
		if (outFile.endsWith(".p12")) {
			pkcs12File = new File(outFile);
		}
		else {
			if (endsWithKnownExtension(outFile)) {
				return -1;
			}
			pkcs12File = new File(outFile + ".p12");
		}

		if (!checkOverwrite(pkcs12File)) {
			return -1;
		}

		KeyPair keyPair = loadKeyPair(keyFile);

		// Certificate files (especially PKCS#7) contain collections, not ordered chains.
		List<X509Certificate> certificates = Arrays.asList(loadCertificates(certFile));
		List<X509Certificate> caCertificates = Collections.emptyList();
		if (caFile != null) {
			X509Certificate[] caCerts;
			try {
				caCerts = loadCertificates(caFile);
			}
			catch (Exception e) {
				caCerts = loadPkcs7Certificates(caFile);
			}
			caCertificates = Arrays.asList(caCerts);
		}
		X509Certificate[] certChain =
			buildCertificateChain(keyPair.getPublic(), certificates, caCertificates);

		char[] pwd = promptForNewPassword("Enter new keystore password:");
		if (pwd == null) {
			return -1;
		}
		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null, null);
			keyStore.setKeyEntry("mykey", keyPair.getPrivate(), pwd, certChain);
			PKIUtils.saveKeyStore(keyStore, pkcs12File, pwd);
		}
		finally {
			Arrays.fill(pwd, (char) 0);
		}

		return 0;
	}

	/**
	 * Select the certificate matching the key and build a validated, leaf-first chain from
	 * unordered certificate bundles. Identical certificates are deduplicated; distinct
	 * certificates matching the key are ambiguous and require a more specific -cert file.
	 * Unrelated certificates are ignored and any valid issuer path may be selected by PKIX.
	 * <p>
	 * This import operation requires an included, valid self-signed CA root. Using that root as
	 * a path-building anchor checks chain consistency only; it does not establish external trust
	 * in the supplied CA. Revocation checking remains disabled for this offline import operation.
	 *
	 * @param publicKey public key corresponding to the supplied private key
	 * @param certificates certificates from the -cert file, including the desired identity
	 * @param caCertificates optional additional certificates from the -cachain file
	 * @return validated chain with the identity first and the self-signed root last
	 * @throws GeneralSecurityException if the identity is missing or ambiguous, or no complete
	 * validated path to an included self-signed CA root can be built
	 */
	static X509Certificate[] buildCertificateChain(PublicKey publicKey,
			Collection<X509Certificate> certificates, Collection<X509Certificate> caCertificates)
			throws GeneralSecurityException {
		Set<X509Certificate> candidates = new LinkedHashSet<>(certificates);
		X509Certificate subjectCert = null;
		for (X509Certificate cert : candidates) {
			if (publicKey.equals(cert.getPublicKey())) {
				if (subjectCert != null) {
					throw new CertificateException(
						"Multiple certificates in -cert file correspond to key file; " +
							"specify only the intended identity certificate.");
				}
				subjectCert = cert;
			}
		}
		if (subjectCert == null) {
			throw new CertificateException("Certificate file does not correspond to key file!");
		}
		subjectCert.checkValidity();
		candidates.addAll(caCertificates);

		Set<TrustAnchor> anchors = new HashSet<>();
		for (X509Certificate cert : candidates) {
			// Do not allow the identity to become its own trust anchor and bypass validation.
			if (cert.equals(subjectCert) || cert.getBasicConstraints() < 0 ||
				!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
				continue;
			}
			boolean[] usage = cert.getKeyUsage();
			if (usage != null && !usage[5]) { // keyCertSign
				continue;
			}
			try {
				// PKIX does not validate the trust anchor itself.
				cert.checkValidity();
				cert.verify(cert.getPublicKey());
				anchors.add(new TrustAnchor(cert, null));
			}
			catch (GeneralSecurityException e) {
				// An invalid or merely self-issued certificate is not a usable root.
			}
		}
		if (anchors.isEmpty()) {
			throw new CertificateException(
				"Incomplete certificate chain: include a valid self-signed CA root.");
		}

		X509CertSelector target = new X509CertSelector();
		target.setCertificate(subjectCert);
		PKIXBuilderParameters params = new PKIXBuilderParameters(anchors, target);
		params.setRevocationEnabled(false);
		params.setMaxPathLength(-1);
		params.addCertStore(CertStore.getInstance("Collection",
			new CollectionCertStoreParameters(candidates)));

		// Building validates the entire path, INCLUDING the subject certificate. Only the root
		// is excluded from the PKIX path; append it to the chain stored in the key store.
		PKIXCertPathBuilderResult result =
			(PKIXCertPathBuilderResult) CertPathBuilder.getInstance("PKIX").build(params);
		List<Certificate> chain = new ArrayList<>(result.getCertPath().getCertificates());
		chain.add(result.getTrustAnchor().getTrustedCert());
		return chain.toArray(new X509Certificate[0]);
	}

	private boolean savePrivateKey(String keyFile, PrivateKey privateKey) throws Exception {
		char[] pwd = promptForNewPassword("Enter new key password:");
		if (pwd == null) {
			return false;
		}
		try {
			File file = new File(keyFile);
			// Create file with  owner-only permissions.
			// The file is never readable by other local users while it holds key material
			try (OutputStream out = FileUtilities.newOwnerPrivateFileOutputStream(file);
					Writer fw = new OutputStreamWriter(out)) {
				JcaPEMWriter pemWriter = new JcaPEMWriter(fw);
				pemWriter.writeObject(privateKey,
					new JcePEMEncryptorBuilder("AES-256-CBC").build(pwd));
				pemWriter.flush();
			}
			return true;
		}
		finally {
			Arrays.fill(pwd, (char) 0);
		}
	}

	private KeyPair loadKeyPair(String keyFile) throws Exception {
		try (FileReader fileReader = new FileReader(keyFile);
				PEMParser pemParser = new PEMParser(fileReader)) {

			Object parsedObject = pemParser.readObject();

			if (parsedObject == null) {
				throw new IOException("The PEM file is empty or invalid.");
			}

			// Assume the key is encrypted
			if (parsedObject instanceof PEMEncryptedKeyPair) {
				// Force user prompt
				char[] pwd = promptForPassword("Enter Key Decryption Password:");
				try {
					// Build the Decryptor using the password
					PEMDecryptorProvider decryptorProvider =
						new JcePEMDecryptorProviderBuilder().setProvider("BC").build(pwd);

					// Decrypt the key pair container
					PEMKeyPair decryptedKeyPair = ((PEMEncryptedKeyPair) parsedObject)
							.decryptKeyPair(decryptorProvider);

					// Convert the entire PEMKeyPair to a standard JCA java.security.KeyPair object
					return new JcaPEMKeyConverter().setProvider("BC").getKeyPair(decryptedKeyPair);
				}
				finally {
					Arrays.fill(pwd, (char) 0);
				}
			}

			throw new IOException(
				"Unsupported keystore: " + parsedObject.getClass().getSimpleName());
		}
	}

	// Parsing preserves no chain-ordering contract; buildCertificateChain establishes the order.
	static X509Certificate[] loadCertificates(String certFile) throws Exception {
		try (FileInputStream fis = new FileInputStream(certFile)) {
			CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
			Collection<? extends java.security.cert.Certificate> certs =
				cf.generateCertificates(fis);
			return certs.toArray(new X509Certificate[0]);
		}
	}

	static X509Certificate[] loadPkcs7Certificates(String filePath) throws Exception {
		try (InputStream fis = new FileInputStream(filePath)) {
			// Read the full stream bytes
			byte[] p7bBytes = fis.readAllBytes();

			// Parse the PKCS#7 structure
			CMSSignedData signedData = new CMSSignedData(p7bBytes);
			Store<X509CertificateHolder> certStore = signedData.getCertificates();
			Collection<X509CertificateHolder> matches = certStore.getMatches(null);

			// Convert Bouncy Castle holders to java.security.X509Certificate
			JcaX509CertificateConverter converter =
				new JcaX509CertificateConverter().setProvider("BC");
			List<X509Certificate> chainList = new ArrayList<>();

			for (X509CertificateHolder holder : matches) {
				chainList.add(converter.getCertificate(holder));
			}

			return chainList.toArray(new X509Certificate[0]);
		}
	}

	private GeneralNames getSubjectAlternativeNames(Map<String, String> dnMap) {
		List<String> subjectAltNames = getSubjectAlternativeNameList(dnMap);
		if (subjectAltNames == null) {
			return null;
		}
		GeneralName[] generalNames = new GeneralName[subjectAltNames.size()];
		for (int i = 0; i < generalNames.length; i++) {
			String san = subjectAltNames.get(i);
			int type = IPAddress.isValid(san) ? GeneralName.iPAddress : GeneralName.dNSName;
			generalNames[i] = new GeneralName(type, san);
		}
		return new GeneralNames(generalNames);
	}

	private List<String> getSubjectAlternativeNameList(Map<String, String> dnMap) {
		String sans = dnMap.get("SANs");
		if (sans != null && !sans.trim().isEmpty()) {
			List<String> list = new ArrayList<>();
			String[] sanArray = sans.split(",");
			for (String san : sanArray) {
				san = san.trim();
				if (!san.isEmpty()) {
					list.add(san);
				}
			}
			if (!list.isEmpty()) {
				return list;
			}
		}
		return null;
	}

	private static Collection<String> knownExtensions =
		Set.of(".p12", ".key", ".crt", ".cert", ".jks", ".pem");

	private boolean endsWithKnownExtension(String filename) {
		String name = filename.toLowerCase();
		for (String ext : knownExtensions) {
			if (name.endsWith(ext)) {
				System.err.println(
					"The -out file should not specify filename extension (" + ext + ")");
				return true;
			}
		}
		return false;
	}

	private boolean checkOverwrite(File file) {
		if (file.exists()) {
			Scanner scanner = new Scanner(System.in);
			System.out.println("File already exists: " + file.getAbsolutePath());
			System.out.print("Overwrite file? [n]:");
			String resp = scanner.nextLine().toLowerCase();
			if (!"y".equals(resp) && !"yes".equals(resp)) {
				return false;
			}
			if (!file.delete()) {
				System.err.println("Failed to remove file.");
				return false;
			}
		}
		return true;
	}

	private X500Name getDN(Map<String, String> dnMap) {

		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);

		String c = dnMap.get("C").trim();
		if (c.length() != 0) {
			builder.addRDN(BCStyle.C, c);
		}

		String st = dnMap.get("ST").trim();
		if (st.length() != 0) {
			builder.addRDN(BCStyle.ST, st);
		}

		String o = dnMap.get("O").trim();
		if (o.length() != 0) {
			builder.addRDN(BCStyle.O, o);
		}

		// Add OU elements in canonical order
		String ous = dnMap.get("OU");
		String[] ouArray = ous.split(",");
		for (int i = ouArray.length - 1; i >= 0; i--) {
			String ou = ouArray[i].trim();
			if (!ou.isEmpty()) {
				builder.addRDN(BCStyle.OU, ou);
			}
		}

		builder.addRDN(BCStyle.CN, dnMap.get("CN"));

		return builder.build();
	}

	private Map<String, String> promptForDnInfo() {
		Map<String, String> dnMap = new HashMap<>();

		Scanner scanner = new Scanner(System.in);

		System.out.println("\nEnter Certificate information:");
		System.out.print("Country Name (2 letter code, optional) []: ");
		dnMap.put("C", scanner.nextLine().trim());

		System.out.print("State or Province Name (optional) []: ");
		dnMap.put("ST", scanner.nextLine().trim());

		System.out.print("Organization Name (optional) []: ");
		dnMap.put("O", scanner.nextLine().trim());

		System.out.print("Organizational Unit Name(s) (comma separated, optional) []: ");
		dnMap.put("OU", scanner.nextLine());

		String cn = "";
		while (cn.isEmpty()) {
			System.out.print("Common Name (e.g. server FQDN or your name): ");
			cn = scanner.nextLine().trim();
		}
		dnMap.put("CN", cn);

		System.out.print("Subject Alternative Names (comma separated) []: ");
		dnMap.put("SANs", scanner.nextLine());

		return dnMap;
	}

	private char[] promptForNewPassword(String passwordPrompt) {
		char[] pwd = new char[0];
		while (pwd.length < MIN_PWD_LENGTH) {
			if (pwd.length != 0) {
				System.err.println("Password too short!");
			}
			Arrays.fill(pwd, (char) 0);
			pwd = promptForPassword(passwordPrompt);
		}
		char[] pwdRepeat = promptForPassword("Reenter password:");
		try {
			if (!Arrays.equals(pwd, pwdRepeat)) {
				System.err.println("Passwords differ!");
				Arrays.fill(pwd, (char) 0);
				return null;
			}
		}
		finally {
			Arrays.fill(pwdRepeat, (char) 0);
		}
		return pwd;
	}

	private char[] promptForPassword(String passwordPrompt) {

		Console console = System.console();
		if (console == null) {

			// Couldn't get console instance, passwords will be in the clear
			passwordPrompt =
				"*** WARNING! Password entry will NOT be masked ***\n" + passwordPrompt;
			System.out.print(passwordPrompt);
			System.out.flush();

			BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
			try {
				return reader.readLine().toCharArray();
			}
			catch (IOException e) {
				throw new RuntimeException(e);
			}
		}

		return console.readPassword("%s", passwordPrompt);
	}

	/**
	 * Display an optional message followed by usage syntax.
	 * 
	 * @param msg optional error message to proceed usage display
	 */
	private void displayUsage(String msg) {
		if (msg != null) {
			System.err.println(msg);
		}
		String invocationName = System.getProperty(INVOCATION_NAME_PROPERTY);
		System.err.println("\nUsage: " + invocationName + " <command> [options]");
		System.err.println("Supported commands:");
		System.err.println("  request -outkey <key-file-filename>");
		System.err.println(
			"      Generate a new private key and a corresponding certificate request");
		System.err.println(
			"  pkcs12 -inkey <key-filename> -cert <cert-filename> [-cachain <cachain-file>] -out <keystore-filename>");
		System.err.println(
			"      Generate a pkcs12 (p12) keystore from a private key and signed-certificate\n" +
				"      chain (omit -out file extension). Certificates may be in any order;\n" +
				"      include all issuing CAs and a self-signed root. The -cert file must\n" +
				"      contain exactly one distinct certificate matching the private key.");
		System.err.println("  pkcs12 -self-signed -out <keystore/cert-filename>");
		System.err.println(
			"      Generate a new self-signed certificate and private key (omit -out file extension)");
		System.err.println();
	}
}
