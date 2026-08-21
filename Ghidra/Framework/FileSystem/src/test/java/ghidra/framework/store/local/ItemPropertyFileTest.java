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
package ghidra.framework.store.local;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import ghidra.util.PropertyFileTest;

public class ItemPropertyFileTest extends PropertyFileTest {

	public ItemPropertyFileTest() {
		super();
	}

	@Override
	protected ItemPropertyFile getPropertyFile() throws IOException {
		return new ItemPropertyFile(storageDir, storageName, "/", NAME);
	}

	@Test
	public void testPropertyFileName() throws Exception {

		ItemPropertyFile pf = getPropertyFile();
		assertEquals(storageName, pf.getStorageName());
		assertEquals(NAME, pf.getName());
		assertEquals("/", pf.getParentPath());
		assertEquals("/" + NAME, pf.getPath());
		pf.writeState();

		pf = getPropertyFile();
		assertTrue(pf.exists());
		assertEquals(storageName, pf.getStorageName());
		assertEquals(NAME, pf.getName());
		assertEquals("/", pf.getParentPath());
		assertEquals("/" + NAME, pf.getPath());

	}

}
