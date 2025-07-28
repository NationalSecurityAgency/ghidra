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
package ghidra.program.disassemble;

import org.junit.*;
import org.junit.rules.TestName;

import db.Transaction;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class ReDisassemblerTest extends AbstractGhidraHeadlessIntegrationTest {
	Language toy;
	final TaskMonitor monitor = new ConsoleTaskMonitor();
	Program program;

	@Rule
	public TestName name = new TestName();

	@Before
	public void setup() throws Exception {
		toy = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("Toy:BE:64:harvard_rev"));
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.release(this);
		}
	}

	@Test
	public void testWhereDefaultSpaceIsDeclaredSecond() throws Exception {
		program = createDefaultProgram(name.getMethodName(), "Toy:BE:64:harvard_rev", this);

		try (Transaction tx = program.openTransaction("Init")) {
			Address start =
				program.getAddressFactory().getDefaultAddressSpace().getAddress(0x00400000);
			Address data =
				program.getAddressFactory().getAddressSpace("data").getAddress(0x00100000);
			program.getMemory()
					.createInitializedBlock(".data", data, 0x1000, (byte) 0, monitor, false);
			program.getMemory()
					.createInitializedBlock(".text", start, 0x1000, (byte) 0, monitor, false);

			Assembler asm = Assemblers.getAssembler(program);
			asm.assemble(start,
				"imm r0, #0x23");

			ReDisassembler rd = new ReDisassembler(program);
			rd.disasemble(start, monitor);
		}
	}
}
