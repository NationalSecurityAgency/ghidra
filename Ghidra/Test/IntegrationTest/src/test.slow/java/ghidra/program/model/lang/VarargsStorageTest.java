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
package ghidra.program.model.lang;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;

public class VarargsStorageTest extends AbstractGenericTest {

	private Program program;

	@Test
	public void test_MSP430_stdcall() throws Exception {

		Language language = SleighLanguageProvider.getSleighLanguageProvider()
				.getLanguage(new LanguageID("TI_MSP430:LE:16:default"));
		ProgramBuilder builder = new ProgramBuilder("test", language);

		program = builder.getProgram();
		PrototypeModel model = program.getCompilerSpec().getCallingConvention("__stdcall");
		DataType intType = new UnsignedIntegerDataType(program.getDataTypeManager());
		DataType voidType = new VoidDataType(program.getDataTypeManager());
		assertNotNull(model);
		DataType[] inputs = new DataType[4];
		inputs[0] = voidType;
		inputs[1] = intType;
		inputs[2] = intType;
		inputs[3] = intType;
		VariableStorage[] storage = model.getStorageLocations(program, inputs, false, false);
		assertEquals(1, storage[1].getVarnodeCount());
		assertEquals("R12", storage[1].getFirstVarnode().toString(language));
		assertEquals(1, storage[2].getVarnodeCount());
		assertEquals("R13", storage[2].getFirstVarnode().toString(language));
		assertEquals(1, storage[3].getVarnodeCount());
		assertEquals("R14", storage[3].getFirstVarnode().toString(language));

		// TI_MSP430 __stdcall passes the last fixed argument of a variadic function
		// on the stack, so storage[3] should be a stack location instead of R14
		storage = model.getStorageLocations(program, inputs, false, true);
		assertEquals(1, storage[1].getVarnodeCount());
		assertEquals("R12", storage[1].getFirstVarnode().toString(language));
		assertEquals(1, storage[2].getVarnodeCount());
		assertEquals("R13", storage[2].getFirstVarnode().toString(language));
		assertEquals(1, storage[3].getVarnodeCount());
		assertTrue(storage[3].isStackStorage());
	}

	@Test
	public void test_avr8__stdcall() throws Exception {

		Language language = SleighLanguageProvider.getSleighLanguageProvider()
				.getLanguage(new LanguageID("avr8:LE:16:default"));
		ProgramBuilder builder = new ProgramBuilder("test", language);

		program = builder.getProgram();
		PrototypeModel model = program.getCompilerSpec().getCallingConvention("__stdcall");
		DataType intType = new UnsignedIntegerDataType(program.getDataTypeManager());
		DataType voidType = new VoidDataType(program.getDataTypeManager());
		assertNotNull(model);
		DataType[] inputs = new DataType[4];
		inputs[0] = voidType;
		inputs[1] = intType;
		inputs[2] = intType;
		inputs[3] = intType;
		VariableStorage[] storage = model.getStorageLocations(program, inputs, false, false);
		assertEquals(1, storage[1].getVarnodeCount());
		assertEquals("R25R24", storage[1].getFirstVarnode().toString(language));
		assertEquals(1, storage[2].getVarnodeCount());
		assertEquals("R23R22", storage[2].getFirstVarnode().toString(language));
		assertEquals(1, storage[3].getVarnodeCount());
		assertEquals("R21R20", storage[3].getFirstVarnode().toString(language));

		// avr8 __stdcall passes all parameters of a variadic function on the stack
		storage = model.getStorageLocations(program, inputs, false, true);
		assertEquals(1, storage[1].getVarnodeCount());
		assertTrue(storage[1].isStackStorage());
		assertEquals(1, storage[2].getVarnodeCount());
		assertTrue(storage[2].isStackStorage());
		assertEquals(1, storage[3].getVarnodeCount());
		assertTrue(storage[3].isStackStorage());
	}

	@Test
	public void test_x64__stdcall() throws Exception {

		Language language = SleighLanguageProvider.getSleighLanguageProvider()
				.getLanguage(new LanguageID("x86:LE:64:default"));
		ProgramBuilder builder = new ProgramBuilder("test", "x86:LE:64:default", "gcc", null);

		program = builder.getProgram();
		PrototypeModel model = program.getCompilerSpec().getCallingConvention("__stdcall");
		DataType longType = new UnsignedLongDataType(program.getDataTypeManager());
		DataType voidType = new VoidDataType(program.getDataTypeManager());
		assertNotNull(model);
		DataType[] inputs = new DataType[4];
		inputs[0] = voidType;
		inputs[1] = longType;
		inputs[2] = longType;
		inputs[3] = longType;
		VariableStorage[] storage = model.getStorageLocations(program, inputs, false, false);
		assertEquals(1, storage[1].getVarnodeCount());
		assertEquals("RDI", storage[1].getFirstVarnode().toString(language));
		assertEquals(1, storage[2].getVarnodeCount());
		assertEquals("RSI", storage[2].getFirstVarnode().toString(language));
		assertEquals(1, storage[3].getVarnodeCount());
		assertEquals("RDX", storage[3].getFirstVarnode().toString(language));

		// x64 gcc __stdcall does not assign parameters differently for variadic functions
		storage = model.getStorageLocations(program, inputs, false, true);
		assertEquals(1, storage[1].getVarnodeCount());
		assertEquals("RDI", storage[1].getFirstVarnode().toString(language));
		assertEquals(1, storage[2].getVarnodeCount());
		assertEquals("RSI", storage[2].getFirstVarnode().toString(language));
		assertEquals(1, storage[3].getVarnodeCount());
		assertEquals("RDX", storage[3].getFirstVarnode().toString(language));
	}

}
