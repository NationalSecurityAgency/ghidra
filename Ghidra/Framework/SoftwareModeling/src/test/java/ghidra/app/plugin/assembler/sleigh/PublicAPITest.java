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
package ghidra.app.plugin.assembler.sleigh;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.assembler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.util.ProgramTransaction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class PublicAPITest extends AbstractGenericTest {
	Language x86;
	Language toy;

	Program program;

	@Before
	public void setUp() throws Exception {
		SleighLanguageProvider provider = new SleighLanguageProvider();
		x86 = provider.getLanguage(new LanguageID("x86:LE:64:default"));
		toy = provider.getLanguage(new LanguageID("Toy:BE:64:default"));
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testADD0() throws AssemblySyntaxException, AssemblySemanticException {
		// Mostly just test that it doesn't crash
		Assembler asm = Assemblers.getAssembler(x86);
		byte[] b =
			asm.assembleLine(x86.getDefaultSpace().getAddress(0x40000000), "ADD byte ptr [RBX],BL");
		assertNotEquals(0, b.length);
	}

	protected Address addr(long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@Test
	public void testAssembleWithDelaySlot() throws Exception,
			AddressOverflowException, CancelledException {
		program = new ProgramDB("test", toy, toy.getDefaultCompilerSpec(), this);

		InstructionIterator it;
		try (ProgramTransaction tid = ProgramTransaction.open(program, "Test")) {
			program.getMemory()
					.createInitializedBlock(".text", addr(0x00400000), 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			Assembler asm = Assemblers.getAssembler(program);

			it = asm.assemble(addr(0x00400000),
				"brds 0x00400004",
				"add r0, #6");

			tid.commit();
		}

		List<Instruction> result = new ArrayList<>();
		while (it.hasNext()) {
			result.add(it.next());
		}

		assertEquals(2, result.size());
		assertEquals("brds", result.get(0).getMnemonicString());
		assertEquals("_add", result.get(1).getMnemonicString());
	}
}
