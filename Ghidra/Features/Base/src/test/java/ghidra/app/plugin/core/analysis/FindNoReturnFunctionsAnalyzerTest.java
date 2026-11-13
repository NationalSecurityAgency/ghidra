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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class FindNoReturnFunctionsAnalyzerTest extends AbstractGenericTest {
	private ProgramBuilder builder;
	private ProgramDB program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("UnmappedNoReturnTarget", ProgramBuilder._X86);
		builder.createMemory(".text", "0x1000", 0x1000);
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testUnmappedNoReturnTargetPreservesFollowingFunctions() throws Exception {
		Address target = builder.addr("0x100000");
		int[] callOffsets = { 0x1100, 0x1200, 0x1300 };
		for (int offset : callOffsets) {
			Address call = builder.addr("0x" + Integer.toHexString(offset));
			Address next = call.add(5);
			byte[] code = ByteBuffer.allocate(6)
					.order(ByteOrder.LITTLE_ENDIAN)
					.put((byte) 0xe8)
					.putInt((int) (target.getOffset() - offset - 5))
					.put((byte) 0xc3)
					.array();
			builder.setBytes(call.toString(), code);
			builder.withTransaction(() -> {
				AddressSet starts = new AddressSet(call, call);
				starts.add(next);
				assertTrue(new DisassembleCommand(starts, new AddressSet(call, next), false)
						.applyTo(program));
			});
			assertEquals(target, program.getListing().getInstructionAt(call).getFlows()[0]);
			builder.createMemoryCallReference(call.toString(), target.toString());
			assertNotNull(builder.createFunction(next.toString()));
		}

		int transaction = program.startTransaction("analyze non-returning target");
		AtomicInteger repairCalls = new AtomicInteger();
		try {
			FindNoReturnFunctionsAnalyzer analyzer = new FindNoReturnFunctionsAnalyzer() {
				@Override
				protected AddressSet findRepairLocations(Program currentProgram, Address entry) {
					repairCalls.incrementAndGet();
					AddressSet seeds = new AddressSet();
					for (int offset : callOffsets) {
						seeds.add(builder.addr("0x" + Integer.toHexString(offset + 5)));
					}
					return seeds;
				}
			};
			analyzer.added(program,
				new AddressSet(builder.addr("0x1100"), builder.addr("0x1305")),
				TaskMonitor.DUMMY, new MessageLog());
		}
		finally {
			program.endTransaction(transaction, true);
		}

		assertNull(program.getFunctionManager().getFunctionAt(target));
		assertEquals("unmapped targets must not schedule flow repair", 0, repairCalls.get());
		for (int offset : callOffsets) {
			Address call = builder.addr("0x" + Integer.toHexString(offset));
			assertEquals("call was not classified as non-returning", FlowOverride.CALL_RETURN,
				program.getListing().getInstructionAt(call).getFlowOverride());
			Address next = builder.addr("0x" + Integer.toHexString(offset + 5));
			assertNotNull("following function was cleared at " + next,
				program.getFunctionManager().getFunctionAt(next));
		}
	}
}
