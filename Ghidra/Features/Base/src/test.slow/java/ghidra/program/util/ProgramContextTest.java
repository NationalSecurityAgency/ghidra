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
package ghidra.program.util;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;

import org.junit.*;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * quick and dirty test of the ProgramContextImpl just to see
 * if the values are being set for specified address range.
 * The ProgramContextPlugin will be a more complete test
 * program, with a gui interface to specify the values and
 * select/highlight an address range.
 */
public class ProgramContextTest extends AbstractGhidraHeadedIntegrationTest {

	private Program program;
	private Memory mem;
	private AddressSpace space;

	public ProgramContextTest() {
		super();
	}

	@Before
	public void setUp() throws IOException {
		Language lang = getSLEIGH_8051_LANGUAGE();
		space = lang.getAddressFactory().getDefaultAddressSpace();

		program = new ProgramDB("8051", lang, lang.getDefaultCompilerSpec(), this);
		mem = program.getMemory();
	}

	@Test
	public void testRegisterNameLookup() {
		ProgramContext programContext = program.getProgramContext();
		boolean didSomething = false;
		for (String regName : programContext.getRegisterNames()) {
			Register reg = programContext.getRegister(regName);
			assertNotNull(reg);
			assertEquals(regName, reg.getName());
			assertTrue(reg == programContext.getRegister(regName.toLowerCase()));
			assertTrue(reg == programContext.getRegister(regName.toUpperCase()));
			didSomething = true;
		}
		assertTrue(didSomething);
	}

	@Test
	public void testAll() {
		int id = program.startTransaction("Test");
		try {

			Address start = getAddress(0);
			try {
				mem.createInitializedBlock("first", start, 100, (byte) 0,
					TaskMonitorAdapter.DUMMY_MONITOR, false);
			}
			catch (Exception e) {
				Assert.fail("TestProgramContext: couldn't add block to memory");
			}

			ProgramContext programContext = program.getProgramContext();
			boolean didSomething = false;

			Address startAddress = start;
			Address endAddress = getAddress(0x30);

			// stick a value into each one!
			BigInteger value = BigInteger.valueOf(255);

			for (Register register : programContext.getRegisters()) {
				Register reg = register;
				if (!reg.isBaseRegister() && reg.isProcessorContext()) {
					continue;
				}
				try {
					programContext.setValue(reg, startAddress, endAddress, value);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				assertNotNull(programContext.getValue(reg, startAddress, false));
				assertNotNull(programContext.getValue(reg, endAddress, false));
				Address insideAddr1 = startAddress.add(10);
				BigInteger val = programContext.getValue(reg, insideAddr1, false);
				assertTrue("unexpected context value for " + reg + ": " + val, value.equals(val));

				Address insideAddr2 = startAddress.add(29);
				assertEquals(value, programContext.getValue(reg, insideAddr2, false));

				Address badAddress = endAddress.add(10);
				assertNull(programContext.getValue(reg, badAddress, false));

				AddressRangeIterator registerValueAddressRanges =
					programContext.getRegisterValueAddressRanges(reg);
				assertTrue(registerValueAddressRanges.hasNext());
				AddressRange range = registerValueAddressRanges.next();
				assertEquals(startAddress, range.getMinAddress());
				assertEquals(endAddress, range.getMaxAddress());
				assertTrue(!registerValueAddressRanges.hasNext());

				registerValueAddressRanges =
					programContext.getRegisterValueAddressRanges(reg, insideAddr1, insideAddr1);
				assertTrue(registerValueAddressRanges.hasNext());
				range = registerValueAddressRanges.next();
				assertEquals(insideAddr1, range.getMinAddress());
				assertEquals(insideAddr1, range.getMaxAddress());
				assertTrue(!registerValueAddressRanges.hasNext());

				range = new AddressRangeImpl(startAddress, endAddress);
				assertEquals(range,
					programContext.getRegisterValueRangeContaining(reg, startAddress));
				assertEquals(range,
					programContext.getRegisterValueRangeContaining(reg, endAddress));
				assertEquals(range,
					programContext.getRegisterValueRangeContaining(reg, insideAddr1));

				assertEquals(
					new AddressRangeImpl(endAddress.next(),
						endAddress.getAddressSpace().getMaxAddress()),
					programContext.getRegisterValueRangeContaining(reg, badAddress));

				didSomething = true;
			}
			assertTrue(didSomething);
		}
		finally {
			program.endTransaction(id, false);
		}
	}

	private Address getAddress(long offset) {
		return space.getAddress(offset);
	}

}
