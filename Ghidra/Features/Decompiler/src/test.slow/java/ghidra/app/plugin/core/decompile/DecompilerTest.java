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
package ghidra.app.plugin.core.decompile;

import java.util.Iterator;

import org.junit.*;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

public class DecompilerTest extends AbstractGhidraHeadedIntegrationTest {
	private Program prog;
	private DecompInterface decompiler;

	@Before
	public void setUp() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder();
		builder.createMemory("test", "0x0", 6);
		builder.addBytesCall(0x0, 0x4);
		builder.addBytesReturn(0x2);
		builder.addBytesReturn(0x4);
		builder.createFunction("0x0");
		builder.createFunction("0x4");
		prog = builder.getProgram();

		decompiler = new DecompInterface();
		decompiler.openProgram(prog);
	}

	@After
	public void tearDown() throws Exception {
		if (decompiler != null) {
			decompiler.dispose();
		}
	}

	@Test
	public void testDecompileInterfaceReturnsAFunction() throws Exception {
		Address addr = prog.getAddressFactory().getDefaultAddressSpace().getAddress(0x0);
		Function func = prog.getListing().getFunctionAt(addr);
		DecompileResults decompResults = decompiler.decompileFunction(func,
			DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		String decompilation = decompResults.getDecompiledFunction().getC();
		Assert.assertNotNull(decompilation);
	}

	@Test
	public void testAnalysisStyleReturnsSemanticCallInformation() throws Exception {
		Assert.assertTrue(decompiler.setSimplificationStyle("analysis"));

		Address entry = prog.getAddressFactory().getDefaultAddressSpace().getAddress(0x0);
		Function function = prog.getListing().getFunctionAt(entry);
		DecompileResults results = decompiler.decompileFunction(function,
			DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);

		Assert.assertTrue(results.decompileCompleted());
		Assert.assertNotNull(results.getHighFunction());
		Iterator<PcodeOpAST> ops = results.getHighFunction().getPcodeOps();
		while (ops.hasNext()) {
			PcodeOpAST op = ops.next();
			if (op.getOpcode() == PcodeOp.CALL) {
				Assert.assertEquals(0x4, op.getInput(0).getOffset());
				return;
			}
		}
		Assert.fail("Analysis style did not recover the direct call");
	}
}
