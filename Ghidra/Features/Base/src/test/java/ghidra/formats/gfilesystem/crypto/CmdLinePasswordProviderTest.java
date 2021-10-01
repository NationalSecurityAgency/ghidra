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

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.List;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.formats.gfilesystem.FSRL;
import util.CollectionUtils;
import utilities.util.FileUtilities;

public class CmdLinePasswordProviderTest extends AbstractGenericTest {

	private CryptoProviders cryptoProviders = CryptoProviders.getInstance();

	private List<PasswordValue> getPasswords(CryptoSession cryptoSession, String fsrlStr)
			throws MalformedURLException {
		return CollectionUtils
				.asList(cryptoSession.getPasswordsFor(FSRL.fromString(fsrlStr), "badbeef"));
	}

	private String origCmdLinePasswordValue;
	private PopupGUIPasswordProvider popupGUIPasswordProvider;

	@Before

	public void setUp() {
		popupGUIPasswordProvider =
			cryptoProviders.getCryptoProviderInstance(PopupGUIPasswordProvider.class);
		cryptoProviders.unregisterCryptoProvider(popupGUIPasswordProvider);
		cryptoProviders.getCachedCryptoProvider().clearCache();
		origCmdLinePasswordValue = System
				.getProperty(CmdLinePasswordProvider.CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME, null);
	}

	@After
	public void tearDown() {
		if (popupGUIPasswordProvider != null) {
			cryptoProviders.registerCryptoProvider(popupGUIPasswordProvider);
		}
		if (origCmdLinePasswordValue == null) {
			System.clearProperty(CmdLinePasswordProvider.CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME);
		}
		else {
			System.setProperty(CmdLinePasswordProvider.CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME,
				origCmdLinePasswordValue);
		}
	}

	@Test
	public void testPassword() throws IOException {
		File pwdFile = createTempFile("password_test");
		FileUtilities.writeStringToFile(pwdFile,
			"password_for_file1.txt\tfile1.txt\n\npassword_for_file2.txt\t/path/to/file2.txt\ngeneral_password\n");

		System.setProperty(CmdLinePasswordProvider.CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME,
			pwdFile.getPath());
		try (CryptoSession cryptoSession = cryptoProviders.newSession()) {
			List<PasswordValue> pwdList =
				getPasswords(cryptoSession, "file:///fake/path/file1.txt");

			assertEquals(2, pwdList.size());
			assertEquals("password_for_file1.txt", String.valueOf(pwdList.get(0).getPasswordChars()));
			assertEquals("general_password", String.valueOf(pwdList.get(1).getPasswordChars()));
		}
	}

	@Test
	public void testPassword2() throws IOException {
		File pwdFile = createTempFile("password_test");
		FileUtilities.writeStringToFile(pwdFile, "password_for_file1.txt\t/path/to/a/file1.txt");

		System.setProperty(CmdLinePasswordProvider.CMDLINE_PASSWORD_PROVIDER_PROPERTY_NAME,
			pwdFile.getPath());
		try (CryptoSession cryptoSession = cryptoProviders.newSession()) {
			List<PasswordValue> pwdList =
				getPasswords(cryptoSession, "file:///not_matching/path/file1.txt");

			assertEquals(0, pwdList.size());

			List<PasswordValue> list2 = getPasswords(cryptoSession, "file:///path/to/a/file1.txt");
			assertEquals(1, list2.size());
		}
	}
}
