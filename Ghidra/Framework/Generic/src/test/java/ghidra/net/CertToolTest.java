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
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.*;
import org.junit.rules.TemporaryFolder;

public class CertToolTest {

	private static KeyPair rootKey;
	private static KeyPair intermediateKey;
	private static KeyPair leafKey;
	private static KeyPair otherKey;
	private static X509Certificate root;
	private static X509Certificate intermediate;
	private static X509Certificate leaf;
	private static X509Certificate otherRoot;
	private static long serial;

	@Rule
	public TemporaryFolder temporaryFolder = new TemporaryFolder();

	@BeforeClass
	public static void createCertificates() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		rootKey = generator.generateKeyPair();
		intermediateKey = generator.generateKeyPair();
		leafKey = generator.generateKeyPair();
		otherKey = generator.generateKeyPair();
		root = certificate("Root", rootKey, "Root", rootKey, true, false);
		intermediate = certificate("Intermediate", intermediateKey, "Root", rootKey, true, false);
		leaf = certificate("Leaf", leafKey, "Intermediate", intermediateKey, false, false);
		otherRoot = certificate("Other", otherKey, "Other", otherKey, true, false);
	}

	private static X509Certificate certificate(String subject, KeyPair key, String issuer,
			KeyPair signer, boolean ca, boolean expired) throws Exception {
		return certificate(subject, key, issuer, signer, new BasicConstraints(ca),
			ca ? KeyUsage.keyCertSign : KeyUsage.digitalSignature, expired);
	}

	private static X509Certificate certificate(String subject, KeyPair key, String issuer,
			KeyPair signer, BasicConstraints constraints, int usage, boolean expired)
			throws Exception {
		long now = System.currentTimeMillis();
		Date start = new Date(now - 86400000L);
		Date end = new Date(now + (expired ? -3600000L : 86400000L));
		JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
			new X500Name("CN=" + issuer), BigInteger.valueOf(++serial), start, end,
			new X500Name("CN=" + subject), key.getPublic());
		builder.addExtension(Extension.basicConstraints, true, constraints);
		builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
		return new JcaX509CertificateConverter().getCertificate(builder.build(
			new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())));
	}

	private X509Certificate[] build(X509Certificate... certs) throws GeneralSecurityException {
		return CertTool.buildCertificateChain(leafKey.getPublic(), Arrays.asList(certs), List.of());
	}

	private void assertRejected(X509Certificate... certs) {
		assertThrows(GeneralSecurityException.class, () -> build(certs));
	}

	@Test
	public void testAllCertificateOrders() throws Exception {
		X509Certificate[][] orders = {
			{ leaf, intermediate, root }, { leaf, root, intermediate },
			{ intermediate, leaf, root }, { intermediate, root, leaf },
			{ root, leaf, intermediate }, { root, intermediate, leaf }
		};
		for (X509Certificate[] order : orders) {
			assertArrayEquals(new X509Certificate[] { leaf, intermediate, root }, build(order));
		}
	}

	@Test
	public void testDuplicatesAndUnrelatedCertificates() throws Exception {
		assertArrayEquals(new X509Certificate[] { leaf, intermediate, root },
			build(otherRoot, root, leaf, root, intermediate, leaf, intermediate));
	}

	@Test
	public void testSeparateCaBundleMayContainDuplicateLeafAnywhere() throws Exception {
		assertArrayEquals(new X509Certificate[] { leaf, intermediate, root },
			CertTool.buildCertificateChain(leafKey.getPublic(), List.of(leaf),
				List.of(root, leaf, intermediate, leaf)));
	}

	@Test
	public void testDirectlyIssuedLeaf() throws Exception {
		X509Certificate direct = certificate("Leaf", leafKey, "Root", rootKey, false, false);
		assertArrayEquals(new X509Certificate[] { direct, root }, build(root, direct));
	}

	@Test
	public void testEmptyOrMismatchedIdentityBundle() {
		assertRejected();
		assertRejected(root, intermediate);
		assertThrows(GeneralSecurityException.class, () -> CertTool.buildCertificateChain(
			leafKey.getPublic(), List.of(root), List.of(leaf, intermediate)));
	}

	@Test
	public void testAmbiguousIdentityCertificates() throws Exception {
		X509Certificate renewed =
			certificate("Leaf", leafKey, "Intermediate", intermediateKey, false, false);
		assertRejected(root, intermediate, leaf, renewed);
	}

	@Test
	public void testExplicitIdentityDisambiguatesCaBundle() throws Exception {
		X509Certificate renewed =
			certificate("Leaf", leafKey, "Intermediate", intermediateKey, false, false);
		assertArrayEquals(new X509Certificate[] { leaf, intermediate, root },
			CertTool.buildCertificateChain(leafKey.getPublic(), List.of(leaf),
				List.of(root, renewed, intermediate)));
	}

	@Test
	public void testMissingRootOrIntermediate() {
		assertRejected(leaf);
		assertRejected(leaf, intermediate);
		assertRejected(leaf, root);
	}

	@Test
	public void testUnrelatedRootDoesNotValidateLeaf() throws Exception {
		X509Certificate direct = certificate("Leaf", leafKey, "Root", rootKey, false, false);
		assertRejected(direct, otherRoot);
	}

	@Test
	public void testExpiredLeaf() throws Exception {
		assertRejected(certificate("Leaf", leafKey, "Root", rootKey, false, true), root);
	}

	@Test
	public void testForgedLeafSignatureWithMatchingIssuerName() throws Exception {
		assertRejected(certificate("Leaf", leafKey, "Root", otherKey, false, false), root);
		assertRejected(certificate("Leaf", leafKey, "Intermediate", otherKey, false, false),
			intermediate, root);
	}

	@Test
	public void testExpiredIntermediate() throws Exception {
		assertRejected(leaf,
			certificate("Intermediate", intermediateKey, "Root", rootKey, true, true), root);
	}

	@Test
	public void testNonCaIntermediate() throws Exception {
		assertRejected(leaf,
			certificate("Intermediate", intermediateKey, "Root", rootKey, false, false), root);
	}

	@Test
	public void testExpiredRoot() throws Exception {
		assertRejected(leaf, intermediate,
			certificate("Root", rootKey, "Root", rootKey, true, true));
	}

	@Test
	public void testSelfIssuedRootWithoutValidSelfSignature() throws Exception {
		assertRejected(leaf, intermediate,
			certificate("Root", rootKey, "Root", otherKey, true, false));
	}

	@Test
	public void testNonCaRoot() throws Exception {
		assertRejected(leaf, intermediate,
			certificate("Root", rootKey, "Root", rootKey, false, false));
	}

	@Test
	public void testIdentityCannotBeItsOwnAnchor() throws Exception {
		assertRejected(certificate("Leaf", leafKey, "Leaf", leafKey, false, false), root);
		assertRejected(certificate("Leaf", leafKey, "Leaf", leafKey, true, false), root);
	}

	@Test
	public void testIssuerCycleCannotReachUnrelatedRoot() throws Exception {
		X509Certificate cycleA =
			certificate("Intermediate", intermediateKey, "Cycle", otherKey, true, false);
		X509Certificate cycleB =
			certificate("Cycle", otherKey, "Intermediate", intermediateKey, true, false);
		assertRejected(leaf, cycleA, cycleB, root);
	}

	@Test
	public void testAlternateCrossSignedIssuerPaths() throws Exception {
		X509Certificate crossSigned =
			certificate("Intermediate", intermediateKey, "Other", otherKey, true, false);
		// The original issuer's root is absent, but the cross-signed path is complete.
		assertArrayEquals(new X509Certificate[] { leaf, crossSigned, otherRoot },
			build(intermediate, leaf, otherRoot, crossSigned));
		// With both roots present, either validated path is acceptable.
		X509Certificate[] chain = build(intermediate, root, leaf, otherRoot, crossSigned);
		assertEquals(leaf, chain[0]);
		assertEquals(3, chain.length);
		assertTrue(Arrays.equals(chain, new X509Certificate[] { leaf, intermediate, root }) ||
			Arrays.equals(chain, new X509Certificate[] { leaf, crossSigned, otherRoot }));
	}

	@Test
	public void testCaKeyUsageMustPermitCertificateSigning() throws Exception {
		assertRejected(leaf, intermediate, certificate("Root", rootKey, "Root", rootKey,
			new BasicConstraints(true), KeyUsage.digitalSignature, false));
		assertRejected(leaf, root, certificate("Intermediate", intermediateKey, "Root", rootKey,
			new BasicConstraints(true), KeyUsage.digitalSignature, false));
	}

	@Test
	public void testIntermediatePathLengthConstraint() throws Exception {
		X509Certificate restricted = certificate("Intermediate", intermediateKey, "Root", rootKey,
			new BasicConstraints(0), KeyUsage.keyCertSign, false);
		X509Certificate subordinate =
			certificate("Subordinate", otherKey, "Intermediate", intermediateKey, true, false);
		X509Certificate endEntity =
			certificate("Leaf", leafKey, "Subordinate", otherKey, false, false);
		assertRejected(endEntity, subordinate, restricted, root);
	}

	@Test
	public void testPemBundleImport() throws Exception {
		File file = temporaryFolder.newFile("bundle.pem");
		StringBuilder pem = new StringBuilder();
		for (X509Certificate cert : List.of(root, leaf, intermediate, leaf)) {
			pem.append("-----BEGIN CERTIFICATE-----\n");
			pem.append(Base64.getMimeEncoder().encodeToString(cert.getEncoded()));
			pem.append("\n-----END CERTIFICATE-----\n");
		}
		Files.writeString(file.toPath(), pem);
		assertArrayEquals(new X509Certificate[] { leaf, intermediate, root },
			build(CertTool.loadCertificates(file.getPath())));
	}

	@Test
	public void testPkcs7BundleImport() throws Exception {
		File file = temporaryFolder.newFile("bundle.p7b");
		CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
		generator.addCertificates(new JcaCertStore(List.of(root, leaf, intermediate)));
		Files.write(file.toPath(), generator.generate(new CMSAbsentContent()).getEncoded());
		assertArrayEquals(new X509Certificate[] { leaf, intermediate, root },
			build(CertTool.loadCertificates(file.getPath())));
		assertArrayEquals(new X509Certificate[] { leaf, intermediate, root },
			build(CertTool.loadPkcs7Certificates(file.getPath())));
	}

	@Test
	public void testNormalizedChainCanBeStoredAndRecovered() throws Exception {
		KeyStore store = KeyStore.getInstance("PKCS12");
		store.load(null, null);
		char[] password = "test-password".toCharArray();
		store.setKeyEntry("identity", leafKey.getPrivate(), password,
			build(root, leaf, intermediate));
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		store.store(bytes, password);
		KeyStore recovered = KeyStore.getInstance("PKCS12");
		recovered.load(new ByteArrayInputStream(bytes.toByteArray()), password);
		assertArrayEquals(new X509Certificate[] { leaf, intermediate, root },
			recovered.getCertificateChain("identity"));
		assertEquals(leafKey.getPrivate(), recovered.getKey("identity", password));
	}
}
