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
package ghidra.framework;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class ApplicationVersionTest extends AbstractGenericTest {

	@Test
	public void testApplicationPropertiesVersion() {
		// We should be able to create an ApplicationVersion object from the application version
		// defined in the application properties file without an exception being thrown.
		new ApplicationVersion(
			Application.getApplicationLayout().getApplicationProperties().getApplicationVersion());
	}

	@Test
	public void testApplicationVersionParsing() {
		assertEquals(new ApplicationVersion("9.0").toString(), "9.0");
		assertEquals(new ApplicationVersion("9.0.0").toString(), "9.0");
		assertEquals(new ApplicationVersion("9.0.0-BETA").toString(), "9.0-BETA");

		assertEquals(new ApplicationVersion("9.1").toString(), "9.1");
		assertEquals(new ApplicationVersion("9.1.1").toString(), "9.1.1");
		assertEquals(new ApplicationVersion("9.1.1-BETA").toString(), "9.1.1-BETA");

		try {
			new ApplicationVersion("9");
			fail("Should not be able to parse only a major version...a minor version is required.");
		}
		catch (IllegalArgumentException e) {
			// Getting here indicates success
		}
	}

	@Test
	public void testApplicationVersionGetters() {
		ApplicationVersion applicationVersion = new ApplicationVersion("9.0.1-BETA");
		assertEquals(applicationVersion.getMajor(), 9);
		assertEquals(applicationVersion.getMinor(), 0);
		assertEquals(applicationVersion.getPatch(), 1);
	}

	@Test
	public void testApplicationVersionEquals() {
		ApplicationVersion applicationVersion1 = new ApplicationVersion("9.0");
		ApplicationVersion applicationVersion2 = new ApplicationVersion("9.0.0");
		assertTrue(applicationVersion1.equals(applicationVersion2));

		applicationVersion1 = new ApplicationVersion("9.0");
		applicationVersion2 = new ApplicationVersion("9.0.0-BETA");
		assertFalse(applicationVersion1.equals(applicationVersion2));

		applicationVersion1 = new ApplicationVersion("9.0.0");
		applicationVersion2 = new ApplicationVersion("9.0.1");
		assertFalse(applicationVersion1.equals(applicationVersion2));

		applicationVersion1 = new ApplicationVersion("9.0");
		applicationVersion2 = new ApplicationVersion("10.0");
		assertNotEquals(applicationVersion1, applicationVersion2);
	}

	@Test
	public void testApplicationVersionCompare() {
		ApplicationVersion applicationVersion1 = new ApplicationVersion("9.0");
		ApplicationVersion applicationVersion2 = new ApplicationVersion("9.0.0-BETA");
		assertTrue(applicationVersion1.compareTo(applicationVersion2) == 0);

		applicationVersion1 = new ApplicationVersion("9.0");
		applicationVersion2 = new ApplicationVersion("10.0");
		assertTrue(applicationVersion1.compareTo(applicationVersion2) < 0);

		applicationVersion1 = new ApplicationVersion("9.0");
		applicationVersion2 = new ApplicationVersion("9.1");
		assertTrue(applicationVersion1.compareTo(applicationVersion2) < 0);

		applicationVersion1 = new ApplicationVersion("9.0");
		applicationVersion2 = new ApplicationVersion("9.0.1");
		assertTrue(applicationVersion1.compareTo(applicationVersion2) < 0);

		applicationVersion1 = new ApplicationVersion("9.0.1");
		applicationVersion2 = new ApplicationVersion("9.0.2");
		assertTrue(applicationVersion1.compareTo(applicationVersion2) < 0);
	}
}
