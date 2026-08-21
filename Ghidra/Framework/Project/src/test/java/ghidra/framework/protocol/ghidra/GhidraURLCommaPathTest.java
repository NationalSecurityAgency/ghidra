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
package ghidra.framework.protocol.ghidra;

import static org.junit.Assert.*;

import java.net.URL;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.framework.model.ProjectLocator;
import ghidra.util.NamingUtilities;

public class GhidraURLCommaPathTest extends AbstractGenericTest {

	@Before
	public void setUp() {
		Handler.registerHandler();
	}

	@Test
	public void testCommaInProjectFilePathRoundTrips() {
		String filePath = "/notepad, 1.exe";
		NamingUtilities.checkName("notepad, 1.exe", null);

		ProjectLocator locator = new ProjectLocator("/tmp", "Test");
		URL url = GhidraURL.makeURL(locator, filePath, null);

		assertEquals(filePath, GhidraURL.getProjectPathname(url));
		assertEquals(locator, GhidraURL.getProjectStorageLocator(url));
	}
}
