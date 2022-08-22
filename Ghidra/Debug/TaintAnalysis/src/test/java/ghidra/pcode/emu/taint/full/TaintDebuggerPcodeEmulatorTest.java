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
package ghidra.pcode.emu.taint.full;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Range;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerPcodeMachine;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.pcode.emu.taint.trace.TaintTracePcodeEmulatorTest;
import ghidra.pcode.emu.taint.trace.TaintTracePcodeExecutorStatePiece;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.DefaultTraceLocation;
import ghidra.trace.model.property.TracePropertyMap;
import ghidra.trace.model.property.TracePropertyMapRegisterSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;

public class TaintDebuggerPcodeEmulatorTest extends AbstractGhidraHeadedDebuggerGUITest {
	private DebuggerStaticMappingService mappingService;
	private DebuggerEmulationService emuService;

	@Before
	public void setUpTaintTest() throws Throwable {
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);
	}

	@Test
	public void testFactoryDiscovered() {
		assertEquals(1,
			emuService.getEmulatorFactories()
					.stream()
					.filter(f -> f instanceof TaintDebuggerPcodeEmulatorFactory)
					.count());
	}

	@Test
	public void testFactoryCreate() throws Exception {
		emuService.setEmulatorFactory(new TaintDebuggerPcodeEmulatorFactory());

		createAndOpenTrace();

		try (UndoableTransaction tid = tb.startTransaction()) {
			tb.getOrAddThread("Threads[0]", 0);
		}

		traceManager.activateTrace(tb.trace);

		TraceSchedule time = TraceSchedule.parse("0:t0-1");
		emuService.emulate(tb.trace, time, TaskMonitor.DUMMY);
		traceManager.activateTime(time);

		DebuggerPcodeMachine<?> emu = emuService.getCachedEmulator(tb.trace, time);
		assertTrue(emu instanceof TaintDebuggerPcodeEmulator);
	}

	@Test
	public void testReadsProgramUsrProperties() throws Exception {
		emuService.setEmulatorFactory(new TaintDebuggerPcodeEmulatorFactory());

		createAndOpenTrace("x86:LE:64:default");
		createProgramFromTrace();

		intoProject(program);
		intoProject(tb.trace);

		programManager.openProgram(program);

		AddressSpace rs = tb.language.getAddressFactory().getRegisterSpace();
		TraceThread thread;
		try (UndoableTransaction tid = tb.startTransaction()) {
			mappingService.addMapping(
				new DefaultTraceLocation(tb.trace, null, Range.atLeast(0L), tb.addr(0x55550000)),
				new ProgramLocation(program, tb.addr(0x00400000)), 0x1000, false);
			thread = tb.getOrAddThread("Threads[0]", 0);
			tb.exec(0, 0, thread, List.of(
				"RIP = 0x55550000;"));
		}
		waitForDomainObject(tb.trace);
		waitForPass(() -> assertEquals(new ProgramLocation(program, tb.addr(0x00400000)),
			mappingService.getOpenMappedLocation(
				new DefaultTraceLocation(tb.trace, null, Range.singleton(0L),
					tb.addr(0x55550000)))));

		try (UndoableTransaction tid = UndoableTransaction.start(program, "Assemble")) {
			program.getMemory()
					.createInitializedBlock(".text", tb.addr(0x00400000), 0x1000, (byte) 0,
						TaskMonitor.DUMMY, false);
			StringPropertyMap progTaintMap = program.getUsrPropertyManager()
					.createStringPropertyMap(TaintTracePcodeExecutorStatePiece.NAME);
			progTaintMap.add(tb.addr(0x00400800), "test_0");
			Assembler asm = Assemblers.getAssembler(program);

			// TODO: I should be able to make this use a RIP-relative address
			asm.assemble(tb.addr(0x00400000),
				"MOV RAX, [0x55550800]"); // was [0x00400800], but fixed address is a problem.
		}

		TraceSchedule time = TraceSchedule.parse("0:t0-1");
		long scratch = emuService.emulate(tb.trace, time, TaskMonitor.DUMMY);

		TracePropertyMap<String> traceTaintMap = tb.trace.getAddressPropertyManager()
				.getPropertyMap(TaintTracePcodeExecutorStatePiece.NAME, String.class);
		TracePropertyMapRegisterSpace<String> taintRegSpace =
			traceTaintMap.getPropertyMapRegisterSpace(thread, 0, false);

		assertEquals(TaintTracePcodeEmulatorTest.makeTaintEntries(tb.trace,
			Range.closed(scratch, -1L), rs, Set.of(0L), "test_0"),
			Set.copyOf(taintRegSpace.getEntries(Range.singleton(scratch), tb.reg("RAX"))));
	}
}
