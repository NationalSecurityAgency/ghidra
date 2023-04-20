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

import static org.junit.Assert.*;

import java.io.IOException;
import java.lang.invoke.MethodHandles;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import org.jdom.JDOMException;
import org.junit.Before;
import org.junit.Test;

import db.Transaction;
import docking.action.DockingActionIf;
import generic.Unique;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.modules.DebuggerStaticMappingServicePlugin;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.TraceRecorder;
import ghidra.async.AsyncUtils;
import ghidra.dbg.model.*;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetMethod.AnnotatedTargetMethod;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.DefaultTargetObjectSchema.DefaultAttributeSchema;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.program.model.address.Address;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Lifespan;

public class DebuggerMethodActionsPluginTest extends AbstractGhidraHeadedDebuggerGUITest {
	public static final XmlSchemaContext SCHEMA_CTX;
	public static final TargetObjectSchema MOD_ROOT_SCHEMA;

	static {
		try {
			SCHEMA_CTX = XmlSchemaContext.deserialize(
				EmptyDebuggerObjectModel.class.getResourceAsStream("test_schema.xml"));
			SchemaBuilder builder =
				new SchemaBuilder(SCHEMA_CTX, SCHEMA_CTX.getSchema(SCHEMA_CTX.name("Thread")));
			SchemaName method = SCHEMA_CTX.name("Method");
			builder.addAttributeSchema(
				new DefaultAttributeSchema("Advance", method, true, true, true), "manual");
			builder.addAttributeSchema(
				new DefaultAttributeSchema("StepExt", method, true, true, true), "manual");
			builder.addAttributeSchema(
				new DefaultAttributeSchema("AdvanceWithFlag", method, true, true, true), "manual");
			builder.addAttributeSchema(
				new DefaultAttributeSchema("Between", method, true, true, true), "manual");
			SCHEMA_CTX.replaceSchema(builder.build());
			MOD_ROOT_SCHEMA = SCHEMA_CTX.getSchema(SCHEMA_CTX.name("Test"));
		}
		catch (IOException | JDOMException e) {
			throw new AssertionError(e);
		}
	}

	DebuggerListingPlugin listingPlugin;
	DebuggerStaticMappingService mappingService;
	DebuggerMethodActionsPlugin methodsPlugin;

	List<String> commands = Collections.synchronizedList(new ArrayList<>());

	@Before
	public void setUpMethodActionsTest() throws Exception {
		listingPlugin = addPlugin(tool, DebuggerListingPlugin.class);
		mappingService = addPlugin(tool, DebuggerStaticMappingServicePlugin.class);
		methodsPlugin = addPlugin(tool, DebuggerMethodActionsPlugin.class);

		mb = new TestDebuggerModelBuilder() {
			@Override
			protected TestDebuggerObjectModel newModel(String typeHint) {
				commands.clear();
				return new TestDebuggerObjectModel(typeHint) {
					@Override
					public TargetObjectSchema getRootSchema() {
						return MOD_ROOT_SCHEMA;
					}

					@Override
					protected TestTargetThread newTestTargetThread(
							TestTargetThreadContainer container, int tid) {
						return new TestTargetThread(container, tid) {
							{
								changeAttributes(List.of(),
									AnnotatedTargetMethod.collectExports(MethodHandles.lookup(),
										testModel, this),
									"Initialize");
							}

							@TargetMethod.Export("Advance")
							public CompletableFuture<Void> advance(
									@TargetMethod.Param(
										description = "The target address",
										display = "Target",
										name = "target") Address target) {
								commands.add("advance(" + target + ")");
								return AsyncUtils.NIL;
							}

							// Takes no address context
							@TargetMethod.Export("StepExt")
							public CompletableFuture<Void> stepExt() {
								commands.add("stepExt");
								return AsyncUtils.NIL;
							}

							// Takes a second required non-default parameter
							@TargetMethod.Export("AdvanceWithFlag")
							public CompletableFuture<Void> advanceWithFlag(
									@TargetMethod.Param(
										description = "The target address",
										display = "Target",
										name = "target") Address address,
									@TargetMethod.Param(
										description = "The flag",
										display = "Flag",
										name = "flag") boolean flag) {
								commands.add("advanceWithFlag(" + address + "," + flag + ")");
								return AsyncUtils.NIL;
							}

							// Takes a second address parameter
							@TargetMethod.Export("Between")
							public CompletableFuture<Void> between(
									@TargetMethod.Param(
										description = "The starting address",
										display = "Start",
										name = "start") Address start,
									@TargetMethod.Param(
										description = "The ending address",
										display = "End",
										name = "end") Address end) {
								commands.add("between(" + start + "," + end + ")");
								return AsyncUtils.NIL;
							}
						};
					}
				};
			}
		};
	}

	protected Collection<TargetMethod> collectMethods(TargetObject object) {
		return object.getModel()
				.getRootSchema()
				.matcherForSuitable(TargetMethod.class, object.getPath())
				.getCachedSuccessors(object.getModel().getModelRoot())
				.values()
				.stream()
				.filter(o -> o instanceof TargetMethod)
				.map(o -> (TargetMethod) o)
				.toList();
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
		createTestModel();
		recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();

		assertEquals(4, collectMethods(mb.testThread1).size());

		createProgramFromTrace(tb.trace);
		programManager.openProgram(program);
		ProgramLocationActionContext ctx =
			new ProgramLocationActionContext(listingPlugin.getProvider(), program,
				new ProgramLocation(program, addr(program, 0)), null, null);
		assertEquals(List.of(), methodsPlugin.getPopupActions(tool, ctx));
	}

	@Test
	public void testGetPopupActions() throws Throwable {
		createTestModel();
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitOn(recorder.requestFocus(mb.testThread1));
		waitRecorder(recorder);
		waitForSwing();

		assertEquals(4, collectMethods(mb.testThread1).size());

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
		assertEquals(List.of("Advance"),
			methodsPlugin.getPopupActions(tool, ctx).stream().map(a -> a.getName()).toList());
	}

	@Test
	public void testMethodInvocation() throws Throwable {
		createTestModel();
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		waitForSwing();
		waitOn(recorder.requestFocus(mb.testThread1));
		waitRecorder(recorder);
		waitForSwing();

		assertEquals(4, collectMethods(mb.testThread1).size());

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

		DockingActionIf advance = Unique.assertOne(methodsPlugin.getPopupActions(tool, ctx));
		assertEquals("Advance", advance.getName());
		performAction(advance, ctx, true);
		waitRecorder(recorder);

		assertEquals(List.of("advance(00400000)"), commands);
	}
}
