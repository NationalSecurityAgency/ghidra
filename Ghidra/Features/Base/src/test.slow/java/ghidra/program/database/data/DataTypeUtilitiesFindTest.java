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
package ghidra.program.database.data;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class DataTypeUtilitiesFindTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private DataTypeManagerDB dataMgr;
	private SymbolTable symTab;

	private GhidraClass a;
	private Namespace ab;
	private GhidraClass aba;
	private Namespace abab;
	private GhidraClass ababa;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		dataMgr = program.getDataTypeManager();
		symTab = program.getSymbolTable();
		program.startTransaction("Test");

		a = symTab.createClass(program.getGlobalNamespace(), "A", SourceType.USER_DEFINED);
		ab = symTab.createNameSpace(a, "B", SourceType.USER_DEFINED); // A::B
		aba = symTab.createClass(ab, "A", SourceType.USER_DEFINED); // A::B::A
		abab = symTab.createNameSpace(aba, "B", SourceType.USER_DEFINED); // A::B::A::B
		ababa = symTab.createClass(abab, "A", SourceType.USER_DEFINED); // A::B::A::B::A

		StructureDataType structA = new StructureDataType("A", 0);

		dataMgr.resolve(structA, null);

		CategoryPath cp = new CategoryPath("/x/A");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

		cp = new CategoryPath("/x/A/B");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

		cp = new CategoryPath("/x/A/B/A");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

		cp = new CategoryPath("/x/A/B/A/B");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

		cp = new CategoryPath("/x/A/B/A/B/A");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

		cp = new CategoryPath("/y/A");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

		cp = new CategoryPath("/y/A/B");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

		cp = new CategoryPath("/y/A/B/A");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

		cp = new CategoryPath("/y/A/B/A/B");
		structA.setCategoryPath(cp);
		// omit struct fro category

		cp = new CategoryPath("/y/A/B/A/B/A");
		structA.setCategoryPath(cp);
		dataMgr.resolve(structA, null);

	}

	@After
	public void tearDown() throws Exception {
		program.release(this);
	}

	private void assertPath(DataType dt, String path) {
		assertNotNull(dt);
		assertEquals(path, dt.getPathName());
	}

	@Test
	public void testFindDataType() {

		DataType dt = DataTypeUtilities.findDataType(dataMgr, program.getGlobalNamespace(), "A",
			Structure.class);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findDataType(dataMgr, null, "A", null);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findDataType(dataMgr, ab, "A", Structure.class);
		assertPath(dt, "/x/A/B/A");

		dt = DataTypeUtilities.findDataType(dataMgr, aba, "A", Structure.class);
		assertPath(dt, "/x/A/B/A/A");

		program.setPreferredRootNamespaceCategoryPath("/y");

		dt = DataTypeUtilities.findDataType(dataMgr, program.getGlobalNamespace(), "A",
			Structure.class);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findDataType(dataMgr, null, "A", null);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findDataType(dataMgr, ab, "A", Structure.class);
		assertPath(dt, "/y/A/B/A");

		dt = DataTypeUtilities.findDataType(dataMgr, aba, "A", Structure.class);
		assertPath(dt, "/y/A/B/A/A");

	}

	@Test
	public void findExistingClassStruct() {

		// NOTE: search gives preference to class structure found in parent-namespace

		DataType dt = DataTypeUtilities.findExistingClassStruct(dataMgr, a);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findExistingClassStruct(dataMgr, aba); // A::B::A
		assertPath(dt, "/x/A/B/A");

		dt = DataTypeUtilities.findExistingClassStruct(dataMgr, ababa); // A::B::A::B::A
		assertPath(dt, "/x/A/B/A/B/A");

		program.setPreferredRootNamespaceCategoryPath("/y");

		dt = DataTypeUtilities.findExistingClassStruct(dataMgr, a);
		assertPath(dt, "/y/A/A"); // not found in parent /y

		dt = DataTypeUtilities.findExistingClassStruct(dataMgr, aba); // A::B::A
		assertPath(dt, "/y/A/B/A");

		dt = DataTypeUtilities.findExistingClassStruct(dataMgr, ababa); // A::B::A::B::A
		assertPath(dt, "/y/A/B/A/B/A/A"); // not found in parent /y/A/B/A/B

	}

	@Test
	public void findNamespaceQualifiedDataType() {

		DataType dt =
			DataTypeUtilities.findNamespaceQualifiedDataType(dataMgr, "A", Structure.class);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findNamespaceQualifiedDataType(dataMgr, "A", null);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findNamespaceQualifiedDataType(dataMgr, "A::A", Structure.class);
		assertPath(dt, "/x/A/A");

		dt = DataTypeUtilities.findNamespaceQualifiedDataType(dataMgr, "A::B::A", Structure.class);
		assertPath(dt, "/x/A/B/A");

		program.setPreferredRootNamespaceCategoryPath("/y");

		dt = DataTypeUtilities.findNamespaceQualifiedDataType(dataMgr, "A", Structure.class);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findNamespaceQualifiedDataType(dataMgr, "A", null);
		assertPath(dt, "/A");

		dt = DataTypeUtilities.findNamespaceQualifiedDataType(dataMgr, "A::A", Structure.class);
		assertPath(dt, "/y/A/A");

		dt = DataTypeUtilities.findNamespaceQualifiedDataType(dataMgr, "A::B::A", Structure.class);
		assertPath(dt, "/y/A/B/A");

	}

}
