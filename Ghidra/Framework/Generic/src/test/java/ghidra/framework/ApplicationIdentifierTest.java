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

public class ApplicationIdentifierTest extends AbstractGenericTest {

	@Test
	public void testApplicationPropertiesIdentifier() {
		// We should be able to create an ApplicationIdentifier object from the application info
		// defined in the application properties file without an exception being thrown.
		new ApplicationIdentifier(Application.getApplicationLayout().getApplicationProperties());
	}

	@Test
	public void testApplicationVersionParsing() {
		ApplicationIdentifier id = new ApplicationIdentifier("Ghidra_9.0.1_public_05212019");
		assertEquals(id.getApplicationName(), "ghidra");
		assertEquals(id.getApplicationVersion(), new ApplicationVersion("9.0.1"));
		assertEquals(id.getApplicationReleaseName(), "PUBLIC");
		assertEquals(id.toString(), "ghidra_9.0.1_PUBLIC");

		try {
			new ApplicationIdentifier("ghidra");
			fail(
				"Should not be able to parse only a name...a version and release name are required.");
		}
		catch (IllegalArgumentException e) {
			// Getting here indicates success
		}

		try {
			new ApplicationIdentifier("ghidra_9.0.1");
			fail(
				"Should not be able to parse only a name and version...a release name is required.");
		}
		catch (IllegalArgumentException e) {
			// Getting here indicates success
		}
	}

	@Test
	public void testApplicationIdentifierEquals() {
		ApplicationIdentifier id1 = new ApplicationIdentifier("ghi dra_9.0_pub lic");
		ApplicationIdentifier id2 = new ApplicationIdentifier("Ghidra_9.0.0_PUBLIC");
		assertEquals(id1, id2);

		id1 = new ApplicationIdentifier("ghidra_9.0_public");
		id2 = new ApplicationIdentifier("Ghidra_9.0.1_PUBLIC");
		assertNotEquals(id1, id2);

		id1 = new ApplicationIdentifier("ghidra_9.0_DEV");
		id2 = new ApplicationIdentifier("ghidra_9.0_PUBLIC");
		assertNotEquals(id1, id2);
	}
}
