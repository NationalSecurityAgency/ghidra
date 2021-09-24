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
package ghidra.app.plugin.core.debug.service.emulation;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Test;
import org.junit.experimental.categories.Category;

import generic.Unique;
import generic.test.category.NightlyCategory;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryRegisterSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSchedule;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;

@Category(NightlyCategory.class) // this may actually be an @PortSensitive test
public class DebuggerEmulationServiceTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected DebuggerEmulationServicePlugin emulationPlugin;

	@Test
	public void testPureEmulation() throws Exception {
		emulationPlugin = addPlugin(tool, DebuggerEmulationServicePlugin.class);

		// TODO: Action enablement doesn't work without CodeBrowser???
		// Probably missing some contextChanged, but I have no provider!
		addPlugin(tool, CodeBrowserPlugin.class);

		createProgram();
		intoProject(program);
		Assembler asm = Assemblers.getAssembler(program);
		Memory memory = program.getMemory();
		Address addrText = addr(program, 0x00400000);
		Register regPC = program.getRegister("pc");
		Register regR0 = program.getRegister("r0");
		Register regR1 = program.getRegister("r1");
		try (UndoableTransaction tid = UndoableTransaction.start(program, "Initialize", true)) {
			MemoryBlock blockText = memory.createInitializedBlock(".text", addrText, 0x1000,
				(byte) 0, TaskMonitor.DUMMY, false);
			blockText.setExecute(true);
			memory.createInitializedBlock(".data", addr(program, 0x00600000), 0x1000, (byte) 0,
				TaskMonitor.DUMMY, false);
			asm.assemble(addrText, "mov r0, r1");
			program.getProgramContext()
					.setValue(regR1, addrText, addrText, new BigInteger("1234", 16));
		}

		programManager.openProgram(program);
		waitForSwing();

		assertTrue(emulationPlugin.actionEmulateProgram.isEnabled());
		performAction(emulationPlugin.actionEmulateProgram);

		Trace trace = traceManager.getCurrentTrace();
		assertNotNull(trace);

		TraceThread thread = Unique.assertOne(trace.getThreadManager().getAllThreads());
		TraceMemoryRegisterSpace regs =
			trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
		assertEquals(new BigInteger("00400000", 16),
			regs.getViewValue(0, regPC).getUnsignedValue());
		assertEquals(new BigInteger("0000", 16), regs.getViewValue(0, regR0).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16), regs.getViewValue(0, regR1).getUnsignedValue());

		long scratch =
			emulationPlugin.emulate(trace, TraceSchedule.parse("0:t0-1"), TaskMonitor.DUMMY);

		assertEquals(new BigInteger("00400002", 16),
			regs.getViewValue(scratch, regPC).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR0).getUnsignedValue());
		assertEquals(new BigInteger("1234", 16),
			regs.getViewValue(scratch, regR1).getUnsignedValue());
	}
}
