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
package ghidra.app.util.opinion;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

public class DefExportLineTest {

	@Test
	public void testExportLineNameOnly() throws IOException {
		DefExportLine export = new DefExportLine("func");
		assertEquals("func", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals(null, export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(null, export.getOtherModuleOrdinal());
		assertEquals(null, export.getOrdinal());
		assertEquals(false, export.isNoName());
		assertEquals(false, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineInternalName() throws IOException {
		DefExportLine export = new DefExportLine("func2=func1");
		assertEquals("func2", export.getName());
		assertEquals("func1", export.getInternalName());
		assertEquals(null, export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(null, export.getOtherModuleOrdinal());
		assertEquals(null, export.getOrdinal());
		assertEquals(false, export.isNoName());
		assertEquals(false, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineOtherModuleExportedName() throws IOException {
		DefExportLine export = new DefExportLine("func2=other_module.func1");
		assertEquals("func2", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals("other_module", export.getOtherModuleName());
		assertEquals("func1", export.getOtherModuleExportedName());
		assertEquals(null, export.getOtherModuleOrdinal());
		assertEquals(null, export.getOrdinal());
		assertEquals(false, export.isNoName());
		assertEquals(false, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineOtherModuleOrdinal() throws IOException {
		DefExportLine export = new DefExportLine("func2=other_module.#42");
		assertEquals("func2", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals("other_module", export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(42, (int) export.getOtherModuleOrdinal());
		assertEquals(null, export.getOrdinal());
		assertEquals(false, export.isNoName());
		assertEquals(false, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineOrdinal() throws IOException {
		DefExportLine export = new DefExportLine("func @1");
		assertEquals("func", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals(null, export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(null, export.getOtherModuleOrdinal());
		assertEquals(1, (int) export.getOrdinal());
		assertEquals(false, export.isNoName());
		assertEquals(false, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineOrdinalSpaces() throws IOException {
		DefExportLine export = new DefExportLine("func @     1");
		assertEquals("func", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals(null, export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(null, export.getOtherModuleOrdinal());
		assertEquals(1, (int) export.getOrdinal());
		assertEquals(false, export.isNoName());
		assertEquals(false, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineOrdinalNoName() throws IOException {
		DefExportLine export = new DefExportLine("func @1 NONAME");
		assertEquals("func", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals(null, export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(null, export.getOtherModuleOrdinal());
		assertEquals(1, (int) export.getOrdinal());
		assertEquals(true, export.isNoName());
		assertEquals(false, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineData() throws IOException {
		DefExportLine export = new DefExportLine("exported_global DATA");
		assertEquals("exported_global", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals(null, export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(null, export.getOtherModuleOrdinal());
		assertEquals(null, export.getOrdinal());
		assertEquals(false, export.isNoName());
		assertEquals(false, export.isPrivate());
		assertEquals(true, export.isData());
	}

	@Test
	public void testExportLinePrivate() throws IOException {
		DefExportLine export = new DefExportLine("func PRIVATE");
		assertEquals("func", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals(null, export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(null, export.getOtherModuleOrdinal());
		assertEquals(null, export.getOrdinal());
		assertEquals(false, export.isNoName());
		assertEquals(true, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineAll() throws IOException {
		DefExportLine export = new DefExportLine("func2=other_module.#42 @ 1 NONAME PRIVATE");
		assertEquals("func2", export.getName());
		assertEquals(null, export.getInternalName());
		assertEquals("other_module", export.getOtherModuleName());
		assertEquals(null, export.getOtherModuleExportedName());
		assertEquals(42, (int) export.getOtherModuleOrdinal());
		assertEquals(1, (int) export.getOrdinal());
		assertEquals(true, export.isNoName());
		assertEquals(true, export.isPrivate());
		assertEquals(false, export.isData());
	}

	@Test
	public void testExportLineWithNoName() {
		try {
			new DefExportLine("   ");
			fail("Did not get a parsing exception with an invalid format");
		}
		catch (IOException e) {
			// expected
		}
	}

	@Test
	public void testExportLineWithInvalidOrdinal() {
		try {
			new DefExportLine("func @ff");
			fail("Did not get a parsing exception with an invalid format");
		}
		catch (IOException e) {
			// expected
		}
	}

	@Test
	public void testExportLineWithInvalidType() {
		try {
			new DefExportLine("func @ 1 INVALID_TYPE");
			fail("Did not get a parsing exception with an invalid format");
		}
		catch (IOException e) {
			// expected
		}
	}
}
