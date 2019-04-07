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

import java.io.File;
import java.security.*;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.X509ExtendedKeyManager;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.security.KeyStorePasswordProvider;

public class ApplicationKeyManagerFactoryTest extends AbstractGenericTest {

	private static final String TEST_PWD = "!test-password!";
	private static final String TEST_IDENTITY = "CN=GhidraTest";
	private static final String ALIAS = "defaultsigkey"; // must be lower case

	private File keystoreFile;

	MyKeyStorePasswordProvider passwordProvider = new MyKeyStorePasswordProvider();

	private static class MyKeyStorePasswordProvider implements KeyStorePasswordProvider {

		int state = 0;

		void cancelNextEntry() {
			state = -1; // cancel next callback
		}

		@Override
		public char[] getKeyStorePassword(String keystorePath, boolean passwordError) {
			if (state < 0) { // entry cancelled
				state = 0;
				return null;
			}
			if (state == 0) { // enter wrong password once 
				state = 1;
				return "BAD".toCharArray();
			}
			assertTrue("Expected error after first password callback", passwordError);
			state = 0;
			return TEST_PWD.toCharArray();
		}
	}

	public ApplicationKeyManagerFactoryTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		KeyStore selfSignedKeyStore = ApplicationKeyManagerUtils.createKeyStore(null, "PKCS12",
			TEST_PWD.toCharArray(), ALIAS, null, TEST_IDENTITY, null, 2);

		keystoreFile = createTempFile("test-key", ".p12");
		keystoreFile.delete();
		ApplicationKeyManagerUtils.exportKeystore(selfSignedKeyStore, keystoreFile,
			TEST_PWD.toCharArray());

		ApplicationKeyManagerFactory.setKeyStorePasswordProvider(passwordProvider);
	}

	@After
	public void tearDown() throws Exception {
		if (keystoreFile != null) {
			keystoreFile.delete();
		}
	}

	@Test
	public void testCancelledPasswordOnSetCertificate() throws Exception {

		assertNull(ApplicationKeyManagerFactory.getKeyStore());
		ApplicationKeyManagerFactory instance = ApplicationKeyManagerFactory.getInstance();
		KeyManager[] keyManagers = instance.getKeyManagers();
		assertEquals(1, keyManagers.length);
		assertTrue("", keyManagers[0] instanceof X509ExtendedKeyManager);
		X509ExtendedKeyManager keyManager = (X509ExtendedKeyManager) keyManagers[0];

		// verify that no certs are installed
		assertNull(keyManager.getCertificateChain(ALIAS));
		assertNull(keyManager.getClientAliases("RSA", null));

		passwordProvider.cancelNextEntry();

		ApplicationKeyManagerFactory.setKeyStore(keystoreFile.getAbsolutePath(), false);

		// verify that no certs are installed
		assertEquals(null, ApplicationKeyManagerFactory.getKeyStore());
		assertNull(keyManager.getCertificateChain(ALIAS));
		assertNull(keyManager.getClientAliases("RSA", null));
	}

	@Test
	public void testSetClearCertificate() throws Exception {

		assertNull(ApplicationKeyManagerFactory.getKeyStore());
		ApplicationKeyManagerFactory instance = ApplicationKeyManagerFactory.getInstance();
		KeyManager[] keyManagers = instance.getKeyManagers();
		assertEquals(1, keyManagers.length);
		assertTrue("", keyManagers[0] instanceof X509ExtendedKeyManager);
		X509ExtendedKeyManager keyManager = (X509ExtendedKeyManager) keyManagers[0];

		// verify that no certs are installed
		assertNull(keyManager.getCertificateChain(ALIAS));
		assertNull(keyManager.getClientAliases("RSA", null));

		ApplicationKeyManagerFactory.setKeyStore(keystoreFile.getAbsolutePath(), false);

		// verify that generated cert is installed
		assertEquals(keystoreFile.getAbsolutePath(), ApplicationKeyManagerFactory.getKeyStore());
		X509Certificate[] chain = keyManager.getCertificateChain(ALIAS);
		assertNotNull(chain);
		String[] aliases = keyManager.getClientAliases("RSA", new Principal[0]); // any CA allowed
		assertEquals(1, aliases.length);
		assertEquals(ALIAS, aliases[0]);
		aliases = keyManager.getServerAliases("RSA", new Principal[0]); // any CA allowed
		assertEquals(1, aliases.length);
		assertEquals(ALIAS, aliases[0]);

		SecureRandom random = new SecureRandom();
		byte[] bytes = new byte[256];
		random.nextBytes(bytes);

		// verify that private key functions properly
		PrivateKey privateKey = keyManager.getPrivateKey(ALIAS);

		String algorithm = chain[0].getSigAlgName();
		Signature sig = Signature.getInstance(algorithm);
		sig.initSign(privateKey);
		sig.update(bytes);
		byte[] signature = sig.sign();

		sig = Signature.getInstance(algorithm);
		sig.initVerify(chain[0]);
		sig.update(bytes);
		if (!sig.verify(signature)) {
			Assert.fail("Incorrect signature");
		}

		// clear keystore
		ApplicationKeyManagerFactory.setKeyStore(null, false);

		// verify that no certs are installed
		assertNull(ApplicationKeyManagerFactory.getKeyStore());
		assertNull(keyManager.getCertificateChain(ALIAS));
		assertNull(keyManager.getClientAliases("RSA", null));

	}

}
