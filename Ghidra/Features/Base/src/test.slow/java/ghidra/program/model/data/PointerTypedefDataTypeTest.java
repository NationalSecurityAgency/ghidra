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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.docking.settings.Settings;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.data.PointerTypedefInspector;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for manipulating data types in the category/data type tree.
 */
public class PointerTypedefDataTypeTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private DataTypeManager dtm;
	private BuiltInDataTypeManager builtInDtm;

	public PointerTypedefDataTypeTest() {
		super();
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x2000);
		return builder.getProgram();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram("notepad");
		dtm = program.getDataTypeManager();
		builtInDtm = BuiltInDataTypeManager.getDataTypeManager();

		program.startTransaction("TEST");
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testBuiltInIBODataTypes() throws Exception {

		DataType dt = builtInDtm.getDataType(CategoryPath.ROOT, IBO32DataType.NAME);
		assertTrue(dt instanceof IBO32DataType);
		assertEquals(IBO32DataType.NAME, dt.getName());
		assertFalse(dt.hasLanguageDependantLength());
		DataType dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof IBO32DataType);
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());

		dt = builtInDtm.getDataType(CategoryPath.ROOT, IBO64DataType.NAME);
		assertTrue(dt instanceof IBO64DataType);
		assertEquals(IBO64DataType.NAME, dt.getName());
		assertFalse(dt.hasLanguageDependantLength());
		dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof IBO64DataType);
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());
	}

	@Test
	public void testPointerTypedef() throws Exception {

		DataType dt = new PointerTypedef(null, CharDataType.dataType, -1, dtm, 0x8);
		assertTrue(dt.hasLanguageDependantLength());
		assertEquals(4, dt.getLength());
		assertTrue(dt instanceof TypeDef);
		assertEquals("char * " + formatAttributes("offset(0x8)"), dt.getName());
		DataType dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertTrue(dbDt instanceof DatabaseObject); // transforms to TypedefDB
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());

		AddressSpace space = PointerTypedefInspector.getPointerAddressSpace((TypeDef) dbDt,
			program.getAddressFactory());
		assertNull(space);

		dt = new PointerTypedef(null, CharDataType.dataType, -1, dtm,
			PointerType.RELATIVE);
		assertTrue(dt.hasLanguageDependantLength());
		assertEquals(4, dt.getLength());
		assertTrue(dt instanceof TypeDef);
		assertEquals("char * " + formatAttributes("relative"), dt.getName());
		dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertTrue(dbDt instanceof DatabaseObject); // transforms to TypedefDB
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());

		assertEquals(PointerType.RELATIVE, PointerTypedefInspector.getPointerType((TypeDef) dbDt));

	}

	@Test
	public void testPointerTypedefWithAddrSpace() throws Exception {

		DataType dt = new PointerTypedef(null, CharDataType.dataType, -1, dtm,
			program.getAddressFactory().getRegisterSpace());
		assertFalse(dt.hasLanguageDependantLength());
		assertEquals(2, dt.getLength());
		assertTrue(dt instanceof TypeDef);
		assertEquals("char *16 " + formatAttributes("space(register)"), dt.getName());
		DataType dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertTrue(dbDt instanceof DatabaseObject); // transforms to TypedefDB
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());

		AddressSpace space = PointerTypedefInspector.getPointerAddressSpace((TypeDef) dbDt,
			program.getAddressFactory());
		assertTrue(program.getAddressFactory().getRegisterSpace().equals(space));

		dt = new PointerTypedef(null, CharDataType.dataType, 4, dtm,
			program.getAddressFactory().getRegisterSpace());
		assertFalse(dt.hasLanguageDependantLength());
		assertEquals(4, dt.getLength());
		assertTrue(dt instanceof TypeDef);
		assertEquals("char *32 " + formatAttributes("space(register)"), dt.getName());
		dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertTrue(dbDt instanceof DatabaseObject); // transforms to TypedefDB
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());

		space = PointerTypedefInspector.getPointerAddressSpace((TypeDef) dbDt,
			program.getAddressFactory());
		assertTrue(program.getAddressFactory().getRegisterSpace().equals(space));
	}

	@Test
	public void testPointerTypedefAutoNaming() throws Exception {

		DataType st = dtm.resolve(new StructureDataType("foo", 10), null);

		DataType dt = new PointerTypedef(null, st, -1, dtm,
			program.getAddressFactory().getRegisterSpace());
		assertFalse(dt.hasLanguageDependantLength());
		assertEquals(2, dt.getLength());
		assertTrue(dt instanceof TypeDef);
		assertEquals("foo *16 " + formatAttributes("space(register)"), dt.getName());
		DataType dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertTrue(dbDt instanceof DatabaseObject); // transforms to TypedefDB
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());

		st.setName("bob");

		// auto-name should update
		assertEquals("bob *16 " + formatAttributes("space(register)"), dbDt.getName());

		Settings settings = dbDt.getDefaultSettings();

		OffsetMaskSettingsDefinition.DEF.setValue(settings, 0x123456789abcdef0L);
		assertEquals("bob *16 " + formatAttributes("space(register),mask(0x123456789abcdef0)"),
			dbDt.getName());

		ComponentOffsetSettingsDefinition.DEF.setValue(settings, 0x123);
		assertEquals(
			"bob *16 " + formatAttributes("space(register),mask(0x123456789abcdef0),offset(0x123)"),
			dbDt.getName());

		OffsetShiftSettingsDefinition.DEF.setValue(settings, 16);
		assertEquals(
			"bob *16 " + formatAttributes(
				"space(register),mask(0x123456789abcdef0),shift(16),offset(0x123)"),
			dbDt.getName());

		PointerTypeSettingsDefinition.DEF.setType(settings, PointerType.IMAGE_BASE_RELATIVE);
		assertEquals(
			"bob *16 " + formatAttributes(
				"image-base-relative,space(register),mask(0x123456789abcdef0),shift(16),offset(0x123)"),
			dbDt.getName());

		st.setName("bill");
		assertEquals(
			"bill *16 " + formatAttributes(
				"image-base-relative,space(register),mask(0x123456789abcdef0),shift(16),offset(0x123)"),
			dbDt.getName());

		PointerTypeSettingsDefinition.DEF.clear(settings);
		assertEquals(
			"bill *16 " + formatAttributes(
				"space(register),mask(0x123456789abcdef0),shift(16),offset(0x123)"),
			dbDt.getName());

		ComponentOffsetSettingsDefinition.DEF.clear(settings);
		assertEquals(
			"bill *16 " + formatAttributes("space(register),mask(0x123456789abcdef0),shift(16)"),
			dbDt.getName());

		// NOTE: Changing address space setting will not alter pointer size

		AddressSpaceSettingsDefinition.DEF.clear(settings);
		assertEquals(
			"bill *16 " + formatAttributes("mask(0x123456789abcdef0),shift(16)"),
			dbDt.getName());

		OffsetShiftSettingsDefinition.DEF.clear(settings);
		assertEquals(
			"bill *16 " + formatAttributes("mask(0x123456789abcdef0)"),
			dbDt.getName());

	}

	@Test
	public void testPointerTypedefEquivalence() throws Exception {

		DataType st = dtm.resolve(new StructureDataType("foo", 10), null);

		TypeDef dt = new PointerTypedef(null, st, -1, dtm,
			program.getAddressFactory().getRegisterSpace());
		assertTrue(dt.isAutoNamed());
		assertFalse(dt.hasLanguageDependantLength());
		assertEquals(2, dt.getLength());
		assertEquals("foo *16 " + formatAttributes("space(register)"), dt.getName());
		TypeDef dbDt = (TypeDef) dtm.resolve(dt, null);
		assertTrue(dbDt instanceof DatabaseObject); // transforms to TypedefDB
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());

		dt = (TypeDef) dt.copy(dtm);
		assertTrue(dbDt == dtm.resolve(dt, null)); // should resolve to same instance

		dt = (TypeDef) dt.copy(dtm);
		PointerTypeSettingsDefinition.DEF.setType(dt.getDefaultSettings(), PointerType.IMAGE_BASE_RELATIVE);
		TypeDef dbDt2 = (TypeDef) dtm.resolve(dt, null);    // should resolve to new instance
		assertTrue(dbDt != dbDt2);
		assertEquals("foo *16 " + formatAttributes("image-base-relative,space(register)"),
			dbDt2.getName());

		PointerTypeSettingsDefinition.DEF.clear(dbDt2.getDefaultSettings());
		assertEquals("foo *16 " + formatAttributes("space(register)") + DataType.CONFLICT_SUFFIX,
			dbDt2.getName());

	}

	@Test
	public void testPointerTypedefEquivalence2() throws Exception {

		DataType st = dtm.resolve(new StructureDataType("foo", 10), null);

		TypeDef dt = new PointerTypedef(null, st, -1, dtm,
			program.getAddressFactory().getRegisterSpace());
		assertTrue(dt.isAutoNamed());
		assertFalse(dt.hasLanguageDependantLength());
		assertEquals(2, dt.getLength());
		assertEquals("foo *16 " + formatAttributes("space(register)"), dt.getName());
		TypeDef dbDt = (TypeDef) dtm.resolve(dt, null);
		assertTrue(dbDt instanceof DatabaseObject); // transforms to TypedefDB
		assertTrue(dt.isEquivalent(dbDt));
		assertEquals(dt.getName(), dbDt.getName());

		TypeDef dt2 = new PointerTypedef("john", st, -1, dtm,
			program.getAddressFactory().getRegisterSpace());
		assertFalse(dt2.isAutoNamed());
		assertFalse(dt2.hasLanguageDependantLength());
		assertEquals(2, dt.getLength());
		assertEquals("john", dt2.getName());
		TypeDef dbDt2 = (TypeDef) dtm.resolve(dt2, null);
		assertTrue(dbDt != dbDt2);
		assertFalse(dbDt.isEquivalent(dbDt2));
		assertFalse(dbDt2.isEquivalent(dbDt));
		assertTrue(dbDt2 instanceof DatabaseObject); // transforms to TypedefDB
		assertTrue(dt2.isEquivalent(dbDt2));
		assertEquals(dt2.getName(), dbDt2.getName());

	}

	private static String formatAttributes(String attrs) {
		StringBuilder buf = new StringBuilder(DataType.TYPEDEF_ATTRIBUTE_PREFIX);
		buf.append(attrs);
		buf.append(DataType.TYPEDEF_ATTRIBUTE_SUFFIX);
		return buf.toString();
	}
}
