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
package ghidra.formats.gfilesystem.crypto;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.formats.gfilesystem.FSRL;
import util.CollectionUtils;

public class CachedPasswordProviderTest extends AbstractGenericTest {
	private CryptoProviders cryptoProviders = CryptoProviders.getInstance();

	private List<PasswordValue> getPasswords(CryptoSession cryptoSession, String fsrlStr)
			throws MalformedURLException {
		return CollectionUtils
				.asList(cryptoSession.getPasswordsFor(FSRL.fromString(fsrlStr), "badbeef"));
	}

	private PopupGUIPasswordProvider popupGUIPasswordProvider;

	@Before
	public void setUp() {
		popupGUIPasswordProvider =
			cryptoProviders.getCryptoProviderInstance(PopupGUIPasswordProvider.class);
		cryptoProviders.unregisterCryptoProvider(popupGUIPasswordProvider);
		cryptoProviders.getCachedCryptoProvider().clearCache();
	}

	@After
	public void tearDown() {
		if (popupGUIPasswordProvider != null) {
			cryptoProviders.registerCryptoProvider(popupGUIPasswordProvider);
		}
	}

	@Test
	public void testPassword() throws IOException {
		try (CryptoSession cryptoSession = cryptoProviders.newSession()) {
			assertEquals(0, getPasswords(cryptoSession, "file:///fake/path/file1.txt").size());

			// shouldn't match passwords: file1.txt to file2.txt
			cryptoSession.addSuccessfulPassword(FSRL.fromString("file:///fake/path/file1.txt"),
				PasswordValue.wrap("password_for_file2.txt".toCharArray()));
			assertEquals(1, getPasswords(cryptoSession, "file:///fake/path/file1.txt").size());
			assertEquals(0, getPasswords(cryptoSession, "file:///fake/path/file2.txt").size());

			// should match file1.txt in 2 directories
			assertEquals(1, getPasswords(cryptoSession, "file:///2nd/fake/path/file1.txt").size());
		}
	}
}
