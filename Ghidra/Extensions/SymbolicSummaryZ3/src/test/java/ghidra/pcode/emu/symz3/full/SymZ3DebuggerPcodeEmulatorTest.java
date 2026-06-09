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
package ghidra.pcode.emu.symz3.full;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.service.emulation.DebuggerEmulationServicePlugin;
import ghidra.app.services.DebuggerEmulationService;
import ghidra.app.services.DebuggerEmulationService.EmulationResult;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.symz3.SymZ3EmulatorFactory;
import ghidra.pcode.emu.symz3.state.SymZ3PcodeEmulator;
import ghidra.pcode.emu.symz3.state.SymZ3PcodeExecutorState;
import ghidra.trace.database.ToyDBTraceBuilder.ToySchemaBuilder;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.schedule.*;
import ghidra.util.Msg;

public class SymZ3DebuggerPcodeEmulatorTest extends AbstractGhidraHeadedDebuggerTest {
	private DebuggerEmulationService emuService;

	@Before
	public void setUpSymTest() throws Throwable {
		emuService = addPlugin(tool, DebuggerEmulationServicePlugin.class);
	}

	@Test
	public void testFactoryDiscovered() {
		assertEquals(1, emuService.getEmulatorFactories()
				.stream()
				.filter(f -> f instanceof SymZ3EmulatorFactory)
				.count());
	}

	protected SchemaContext buildContext() {
		return new ToySchemaBuilder()
				.noRegisterGroups()
				.useRegistersPerFrame()
				.build();
	}

	@Test
	public void testFactoryCreate() throws Exception {
		emuService.setEmulatorFactory(new SymZ3EmulatorFactory());

		createAndOpenTrace();

		TraceThread thread;
		try (Transaction tid = tb.startTransaction()) {
			tb.createRootObject(buildContext(), "Target");
			thread = tb.getOrAddThread("Threads[0]", 0);
			tb.createObjectsFramesAndRegs(thread, Lifespan.nowOn(0), tb.host, 1);
		}

		traceManager.activateTrace(tb.trace);

		EmulationResult result =
			emuService.run(tb.host, TraceSchedule.snap(0), monitor, new Scheduler() {
				int calls = 0;

				@Override
				public TickStep nextSlice(Trace trace) {
					// Expect decode of uninitialized memory immediately
					assertEquals(0, calls++);
					return new TickStep(thread.getKey(), 1);
				}
			});

		PcodeMachine<?> emu = emuService.getCachedEmulator(tb.trace, result.schedule());
		assertTrue(emu instanceof SymZ3PcodeEmulator);

		SymZ3PcodeExecutorState state = (SymZ3PcodeExecutorState) emu.getSharedState();
		Msg.debug(this, "here is your state: " + state);
	}
}
