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
package ghidra.app.plugin.core.debug.gui.control;

import static org.junit.Assert.assertEquals;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import docking.action.DockingActionIf;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerIntegrationTest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.plugin.core.debug.service.tracermi.TestTraceRmiConnection.*;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.dbg.target.schema.EnumerableTargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Lifespan;

public class DebuggerMethodActionsPluginTest extends AbstractGhidraHeadedDebuggerIntegrationTest {
	DebuggerListingPlugin listingPlugin;
	DebuggerStaticMappingService mappingService;
	DebuggerMethodActionsPlugin methodsPlugin;

	List<String> commands = Collections.synchronizedList(new ArrayList<>());
	TestRemoteMethod rmiMethodAdvance;
	TestRemoteMethod rmiMethodStepExt;
	TestRemoteMethod rmiMethodAdvanceWithFlag;
	TestRemoteMethod rmiMethodBetween;

	@Before
	public void setUpMethodActionsTest() throws Exception {
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		methodsPlugin = addPlugin(tool, DebuggerMethodActionsPlugin.class);
	}

	protected void addMethods() {
		TestRemoteMethodRegistry reg = rmiCx.getMethods();

		rmiMethodAdvance = new TestRemoteMethod("advance", null, "Advance",
			"Advance to the given address", EnumerableTargetObjectSchema.VOID,
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to advance"),
			new TestRemoteParameter("target", EnumerableTargetObjectSchema.ADDRESS, true, null,
				"Target", "The target address"));
		reg.add(rmiMethodAdvance);

		rmiMethodStepExt = new TestRemoteMethod("step_ext", null, "StepExt",
			"Step in some special way", EnumerableTargetObjectSchema.VOID,
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to step"));
		reg.add(rmiMethodStepExt);

		rmiMethodAdvanceWithFlag = new TestRemoteMethod("advance_flag", null, "Advance With Flag",
			"Advance to the given address, with flag", EnumerableTargetObjectSchema.VOID,
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to advance"),
			new TestRemoteParameter("target", EnumerableTargetObjectSchema.ADDRESS, true, null,
				"Target", "The target address"),
			new TestRemoteParameter("flag", EnumerableTargetObjectSchema.BOOL, true, null,
				"Flag", "The flag"));
		reg.add(rmiMethodAdvanceWithFlag);

		rmiMethodBetween = new TestRemoteMethod("between", null, "Between",
			"Advance between two given addresses", EnumerableTargetObjectSchema.VOID,
			new TestRemoteParameter("thread", new SchemaName("Thread"), true, null, "Thread",
				"The thread to advance"),
			new TestRemoteParameter("start", EnumerableTargetObjectSchema.ADDRESS, true, null,
				"Start", "The starting address"),
			new TestRemoteParameter("end", EnumerableTargetObjectSchema.ADDRESS, true, null,
				"End", "The ending address"));
		reg.add(rmiMethodBetween);
	}

	@Test
	public void testGetPopupActionsNoTrace() throws Throwable {
		createProgram();
		programManager.openProgram(program);
		ProgramLocationActionContext ctx =
			new ProgramLocationActionContext(listingPlugin.getProvider(), program,
				new ProgramLocation(program, addr(program, 0)), null, null);
		assertEquals(List.of(), methodsPlugin.getPopupActions(tool, ctx));
	}

	@Test
	public void testGetPopupActionsNoThread() throws Throwable {
		createRmiConnection();
		addMethods();
		createTrace();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		rmiCx.publishTarget(tool, tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		createProgramFromTrace(tb.trace);
		programManager.openProgram(program);
		// TODO: I think the real reason for empty is the address is not mappable
		ProgramLocationActionContext ctx =
			new ProgramLocationActionContext(listingPlugin.getProvider(), program,
				new ProgramLocation(program, addr(program, 0)), null, null);
		traceManager.activateObject(tb.obj("Processes[1]"));
		waitForSwing();
		assertEquals(List.of(), methodsPlugin.getPopupActions(tool, ctx));
	}

	@Test
	public void testGetPopupActions() throws Throwable {
		createRmiConnection();
		addMethods();
		createTrace();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		rmiCx.publishTarget(tool, tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateObject(tb.obj("Processes[1].Threads[1]"));

		createProgramFromTrace(tb.trace);
		intoProject(program);

		try (Transaction tx = program.openTransaction("Add memory")) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 0x1000,
						(byte) 0, monitor, false);
		}

		try (Transaction tx = tb.startTransaction()) {
			mappingService.addIdentityMapping(tb.trace, program, Lifespan.ALL, true);
		}
		waitForDomainObject(tb.trace);
		waitOn(mappingService.changesSettled());

		programManager.openProgram(program);
		ProgramLocationActionContext ctx =
			new ProgramLocationActionContext(listingPlugin.getProvider(), program,
				new ProgramLocation(program, addr(program, 0x00400000)), null, null);
		// TODO: Should "Between" be included, too?
		assertEquals(Set.of("Advance", "Advance With Flag"),
			methodsPlugin.getPopupActions(tool, ctx)
					.stream()
					.map(a -> a.getName())
					.collect(Collectors.toSet()));
	}

	@Test
	public void testMethodInvocation() throws Throwable {
		createRmiConnection();
		addMethods();
		createTrace();

		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
		}
		rmiCx.publishTarget(tool, tb.trace);

		traceManager.openTrace(tb.trace);
		traceManager.activateObject(tb.obj("Processes[1].Threads[1]"));

		createProgramFromTrace(tb.trace);
		intoProject(program);

		try (Transaction tx = program.openTransaction("Add memory")) {
			program.getMemory()
					.createInitializedBlock(".text", addr(program, 0x00400000), 0x1000,
						(byte) 0, monitor, false);
		}

		try (Transaction tx = tb.startTransaction()) {
			mappingService.addIdentityMapping(tb.trace, program, Lifespan.ALL, true);
		}
		waitForDomainObject(tb.trace);
		waitOn(mappingService.changesSettled());

		programManager.openProgram(program);
		ProgramLocationActionContext ctx =
			new ProgramLocationActionContext(listingPlugin.getProvider(), program,
				new ProgramLocation(program, addr(program, 0x00400000)), null, null);

		DockingActionIf advance = methodsPlugin.getPopupActions(tool, ctx)
				.stream()
				.filter(a -> a.getName().equals("Advance"))
				.findFirst()
				.orElseThrow();
		performAction(advance, ctx, false);

		assertEquals(Map.ofEntries(
			Map.entry("thread", tb.obj("Processes[1].Threads[1]")),
			Map.entry("target", tb.addr(0x00400000))),
			rmiMethodAdvance.expect());
		rmiMethodAdvance.result(null);
	}
}
