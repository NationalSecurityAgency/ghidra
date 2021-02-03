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
package ghidra.util.data;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.plugin.core.compositeeditor.AbstractEditorTest;
import ghidra.app.plugin.core.compositeeditor.UnionEditorProvider;
import ghidra.program.model.data.*;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.DuplicateNameException;

public class DataTypeParserTest extends AbstractEditorTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		Union dt = simpleUnion;
		Category cat = pgmBbCat;

		boolean commit = true;
		startTransaction("Structure Editor Test Initialization");
		try {
			DataTypeManager dataTypeManager = cat.getDataTypeManager();
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = dt.clone(dataTypeManager);
			}
			CategoryPath categoryPath = cat.getCategoryPath();
			if (!dt.getCategoryPath().equals(categoryPath)) {
				try {
					dt.setCategoryPath(categoryPath);
				}
				catch (DuplicateNameException e) {
					commit = false;
					Assert.fail(e.getMessage());
				}
			}
		}
		finally {
			endTransaction(commit);
		}
		final Union unionDt = dt;
		runSwing(() -> installProvider(new UnionEditorProvider(plugin, unionDt, false)));
		txId = program.startTransaction("Modify Program");
	}

	@Override
	@After
	public void tearDown() throws Exception {
		program.endTransaction(txId, true);
		runSwing(() -> provider.dispose());

		super.tearDown();
	}

	@Test
	public void testParse_NameWithTemplate() throws Exception {

		String typeName = "templated_name<int, void*, custom_type>";
		StructureDataType structure = new StructureDataType(typeName, 0);

		tx(program, () -> {
			programDTM.resolve(structure, null);
		});

		DataTypeParser parser = new DataTypeParser(dtmService, AllowedDataTypes.ALL);
		DataType dt = parser.parse(typeName);
		assertNotNull(dt);
		assertTrue(dt.isEquivalent(structure));
	}

	@Test
	public void testParse_PointerToNameWithTemplate() throws Exception {

		//
		// Attempt to resolve a pointer to an existing type when that pointer does not already
		// exist.
		//

		String typeName = "templated_name<int, void*, custom_type>";
		StructureDataType structure = new StructureDataType(typeName, 0);
		PointerDataType pointer = new PointerDataType(structure);
		String pointerName = pointer.getName();

		tx(program, () -> {
			programDTM.resolve(structure, null);
		});

		DataTypeParser parser = new DataTypeParser(dtmService, AllowedDataTypes.ALL);
		DataType dt = parser.parse(pointerName);
		assertNotNull(dt);
		assertTrue(dt.isEquivalent(pointer));
	}

	@Test
	public void testValidDataTypeSyntax() {
		checkValidDt("byte");
		checkValidDt("pointer");
		checkValidDt("pointer8");
		checkValidDt("pointer16");
		checkValidDt("pointer32");
		checkValidDt("pointer64");
		checkValidDt("pointer*");
		checkValidDt("pointer16*");
		checkValidDt("pointer*16");
		checkValidDt("byte*");
		checkValidDt("byte*8");
		checkValidDt("byte*16");
		checkValidDt("byte*32");
		checkValidDt("byte*64");
		checkValidDt("byte***");
		checkValidDt("byte*64*32**16*8");
		checkValidDt("byte*8*");
		checkValidDt("byte*32*16*32");
		checkValidDt("byte[5]");
		checkValidDt("byte[22][13]");
		checkValidDt("byte*[2]");
		checkValidDt("pointer*8[4]");
		checkValidDt("pointer*16*8[13][5]");
		checkValidDt("byte*32*[6][3]*16[4]*");
	}

	@Test
	public void testInvalidDataTypeSyntax() {
		checkInvalidDt("aaa*{");
		checkInvalidDt("byte*5");
		checkInvalidDt("byte*16*[.]");
		checkInvalidDt("byte[]");
		checkInvalidDt("byte[0]");
		checkInvalidDt("*byte");
		checkInvalidDt("byte[7]*[12a]");
		checkInvalidDt("*");
		checkInvalidDt("[2]");
		checkInvalidDt("*[2]");
		checkInvalidDt("byte][2]");
		checkInvalidDt("byte[123");
	}

	@Test
	public void testFactoryTypes() {

		checkValidDt("TerminatedCString");
		checkValidDt("TerminatedCString*");

		checkInvalidDt("TerminatedCString[2]");
		checkInvalidDt("TerminatedCString[]");
		checkInvalidDt("TerminatedCString[2]*");
		checkInvalidDt("TerminatedCString[]*");

		checkInvalidDt("ELF", AllowedDataTypes.DYNAMIC);
		checkInvalidDt("ELF", AllowedDataTypes.SIZABLE_DYNAMIC);
		checkInvalidDt("ELF", AllowedDataTypes.FIXED_LENGTH);

		checkValidDt("ELF*", AllowedDataTypes.DYNAMIC);
		checkValidDt("ELF*", AllowedDataTypes.SIZABLE_DYNAMIC);
		checkValidDt("ELF*", AllowedDataTypes.FIXED_LENGTH);
	}

	@Test
	public void testDynamicTypes() {

		checkValidDt("string", AllowedDataTypes.ALL);
		checkValidDt("string", AllowedDataTypes.DYNAMIC);
		checkValidDt("string", AllowedDataTypes.SIZABLE_DYNAMIC);
		checkInvalidDt("string", AllowedDataTypes.FIXED_LENGTH);

		checkValidDt("string*", AllowedDataTypes.ALL);
		checkValidDt("string*", AllowedDataTypes.DYNAMIC);
		checkValidDt("string*", AllowedDataTypes.SIZABLE_DYNAMIC);
		checkValidDt("string*", AllowedDataTypes.FIXED_LENGTH);

		checkValidDt("string*[2]", AllowedDataTypes.ALL);
		checkValidDt("string*[2]", AllowedDataTypes.DYNAMIC);
		checkValidDt("string*[2]", AllowedDataTypes.SIZABLE_DYNAMIC);
		checkValidDt("string*[2]", AllowedDataTypes.FIXED_LENGTH);

		checkValidDt("GIF-Image", AllowedDataTypes.ALL);
		checkValidDt("GIF-Image", AllowedDataTypes.DYNAMIC);
		checkInvalidDt("GIF-Image", AllowedDataTypes.SIZABLE_DYNAMIC);
		checkInvalidDt("GIF-Image", AllowedDataTypes.FIXED_LENGTH);

		checkValidDt("GIF-Image*", AllowedDataTypes.ALL);
		checkValidDt("GIF-Image*", AllowedDataTypes.DYNAMIC);
		checkValidDt("GIF-Image*", AllowedDataTypes.SIZABLE_DYNAMIC);
		checkValidDt("GIF-Image*", AllowedDataTypes.FIXED_LENGTH);

		checkValidDt("GIF-Image*[2]", AllowedDataTypes.ALL);
		checkValidDt("GIF-Image*[2]", AllowedDataTypes.DYNAMIC);
		checkValidDt("GIF-Image*[2]", AllowedDataTypes.SIZABLE_DYNAMIC);
		checkValidDt("GIF-Image*[2]", AllowedDataTypes.FIXED_LENGTH);

	}

	private void checkValidDt(String dtString) {
		try {
			DataTypeParser parser =
				new DataTypeParser(programDTM, programDTM, dtmService, AllowedDataTypes.ALL);
			DataType dt = parser.parse(dtString);
			assertNotNull(dt);
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	private void checkValidDt(String dtString, AllowedDataTypes allowableTypes) {
		try {
			DataTypeParser parser =
				new DataTypeParser(programDTM, programDTM, dtmService, allowableTypes);
			DataType dt = parser.parse(dtString);
			assertNotNull(dt);
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	private void checkInvalidDt(String dtString) {
		try {
			DataTypeParser parser =
				new DataTypeParser(programDTM, programDTM, dtmService, AllowedDataTypes.ALL);
			parser.parse(dtString);
			Assert.fail(dtString + " should have been invalid.");
		}
		catch (InvalidDataTypeException e) {
			// good
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

	private void checkInvalidDt(String dtString, AllowedDataTypes allowableTypes) {
		try {
			DataTypeParser parser =
				new DataTypeParser(programDTM, programDTM, dtmService, allowableTypes);
			parser.parse(dtString);
			Assert.fail(dtString + " should have been invalid.");
		}
		catch (InvalidDataTypeException e) {
			// good
		}
		catch (Exception e) {
			Assert.fail(e.getMessage());
		}
	}

}
