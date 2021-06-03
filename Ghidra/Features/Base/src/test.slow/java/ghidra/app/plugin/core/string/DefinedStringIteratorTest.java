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
package ghidra.app.plugin.core.string;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.*;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.util.string.FoundString;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;

public class DefinedStringIteratorTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramDB program;
	private ArrayDataType arrayDataType;

	public DefinedStringIteratorTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("TestGhidraSearches", false);
		builder.createMemory("test", "0x0", 0x2000);
		builder.createEncodedString("0x100", "This is the first string", StandardCharsets.US_ASCII,
			true);

		builder.createEncodedString("0x200", "The 0001 string", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("0x210", "The 0002 string", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("0x230", "The 0003 string", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("0x300", "The 0004 string", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("0x310", "The 0005 string", StandardCharsets.US_ASCII, false);

		builder.clearCodeUnits("0x200", "0x400", false);

		StructureDataType struct = new StructureDataType("Test", 0);
		struct.add(new StringDataType(), 0x10);
		struct.add(new StringDataType(), 0x10);
		struct.add(new DWordDataType());
		struct.add(new DWordDataType());
		struct.add(new DWordDataType());
		struct.add(new DWordDataType());
		struct.add(new StringDataType(), 0x10);

		builder.applyDataType("0x200", struct);

		arrayDataType = new ArrayDataType(new StringDataType(), 2, 16);
		builder.applyDataType("0x300", arrayDataType);

		builder.createEncodedString("0x500", "This is the last string", StandardCharsets.US_ASCII,
			false);

		ArrayDataType charArray = new ArrayDataType(new CharDataType(), 50, 1);
		builder.createString("0x600", "The 600 chararray", StandardCharsets.US_ASCII, true,
			charArray);

		// create an empty area for tests to do their own thing
		builder.createUninitializedMemory("uninitialized", "0x3000", 0x1000);
		builder.applyDataType("0x3100", charArray);
		builder.applyFixedLengthDataType("0x3200", new StringDataType(), 10);

		program = builder.getProgram();

	}

	@Test
	public void testIterator() throws Exception {
		DefinedStringIterator iterator = new DefinedStringIterator(program, false);

		assertTrue(iterator.hasNext());
		FoundString foundString = iterator.next();
		assertEquals(addr(0x100), foundString.getAddress());
		assertEquals("This is the first string", foundString.getString(program.getMemory()));

		assertTrue(iterator.hasNext());
		foundString = iterator.next();
		assertEquals(addr(0x200), foundString.getAddress());
		assertEquals("The 0001 string", foundString.getString(program.getMemory()));

		assertTrue(iterator.hasNext());
		foundString = iterator.next();
		assertEquals(addr(0x210), foundString.getAddress());
		assertEquals("The 0002 string", foundString.getString(program.getMemory()));

		assertTrue(iterator.hasNext());
		foundString = iterator.next();
		assertEquals(addr(0x230), foundString.getAddress());
		assertEquals("The 0003 string", foundString.getString(program.getMemory()));

		assertTrue(iterator.hasNext());
		foundString = iterator.next();
		assertEquals(addr(0x300), foundString.getAddress());
		assertEquals("The 0004 string", foundString.getString(program.getMemory()));

		assertTrue(iterator.hasNext());
		foundString = iterator.next();
		assertEquals(addr(0x310), foundString.getAddress());
		assertEquals("The 0005 string", foundString.getString(program.getMemory()));

		assertTrue(iterator.hasNext());
		foundString = iterator.next();
		assertEquals(addr(0x500), foundString.getAddress());
		assertEquals("This is the last string", foundString.getString(program.getMemory()));

		assertTrue(iterator.hasNext());
		foundString = iterator.next();
		assertEquals(addr(0x600), foundString.getAddress());
		assertEquals("The 600 chararray", foundString.getString(program.getMemory()));

		assertFalse(iterator.hasNext());
	}

	@Test
	public void testDataTypeWithNoString_GT_1107() {

		//
		// This code triggers an NPE with the bug unfixed.  Also, we should not examine data
		// found in uninitialized memory.
		//
		Address charArrayAddress = createCharArrayInUninitializedMemory();

		initializeStringModel();

		DefinedStringIterator iterator = new DefinedStringIterator(program, true);
		while (iterator.hasNext()) {
			FoundString string = iterator.next();
			Address address = string.getAddress();
			Assert.assertNotEquals(charArrayAddress, address);
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private Address createCharArrayInUninitializedMemory() {
		CharDataType dataType = new CharDataType();
		ArrayDataType array = new ArrayDataType(dataType, 10, 1);
		Address charArrayAddress = addr(0x3010); // in uninitialized memory
		CreateDataCmd cmd = new CreateDataCmd(charArrayAddress, array);
		assertTrue(applyCmd(program, cmd));
		return charArrayAddress;
	}

	private void initializeStringModel() {
		try {
			NGramUtils.startNewSession("StringModel.sng", false);
		}
		catch (IOException e) {
			failWithException(e.getMessage(), e);
		}
	}

	Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

}
