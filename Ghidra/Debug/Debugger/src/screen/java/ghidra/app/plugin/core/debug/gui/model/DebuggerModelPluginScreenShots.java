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
package ghidra.app.plugin.core.debug.gui.model;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.jdom.JDOMException;
import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.dbg.target.TargetEventScope;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.program.database.ProgramBuilder;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.database.target.DBTraceObjectValue;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerModelPluginScreenShots extends GhidraScreenShotGenerator {
	public static final String CTX_XML = """
			<context>
				<schema name="Session">
					<interface name="Aggregate" />
					<interface name="EventScope" />
					<attribute name="Available" schema="AvailableContainer" />
					<attribute name="Processes" schema="ProcessContainer" />
				</schema>
				<schema name="AvailableContainer" />
				<schema name="ProcessContainer">
					<element schema="Process" />
				</schema>
				<schema name="Process">
					<interface name="Activatable" />
					<interface name="Process" />
					<attribute name="Breakpoints" schema="BreakpointContainer" />
					<attribute name="Threads" schema="ThreadContainer" />
					<attribute name="Memory" schema="Memory" />
					<attribute name="Modules" schema="ModuleContainer" />
				</schema>
				<schema name="BreakpointContainer" canonical="yes">
					<interface name="BreakpointSpecContainer" />
					<interface name="BreakpointLocationContainer" />
					<element schema="Breakpoint" />
				</schema>
				<schema name="Breakpoint">
					<interface name="BreakpointSpec" />
					<interface name="BreakpointLocation" />
				</schema>
				<schema name="ThreadContainer" canonical="yes">
					<element schema="Thread" />
				</schema>
				<schema name="Thread">
					<interface name="Activatable" />
					<interface name="Thread" />
					<attribute name="Registers" schema="RegisterContainer" />
					<attribute name="Stack" schema="Stack" />
				</schema>
				<schema name="Memory" canonical="yes">
					<element schema="MemoryRegion" />
				</schema>
				<schema name="MemoryRegion">
					<interface name="MemoryRegion" />
				</schema>
				<schema name="RegisterContainer">
					<interface name="RegisterContainer" />
				</schema>
				<schema name="Stack" canonical="yes">
					<interface name="Stack" />
					<element schema="StackFrame" />
				</schema>
				<schema name="StackFrame">
					<interface name="Activatable" />
					<interface name="StackFrame" />
					<attribute name="PC" schema="ADDRESS" />
					<attribute-alias from="_pc" to="PC" />
				</schema>
				<schema name="ModuleContainer" canonical="yes">
					<interface name="ModuleContainer" />
				</schema>
			</context>""";
	public static final SchemaContext CTX;

	static {
		try {
			CTX = XmlSchemaContext.deserialize(CTX_XML);
		}
		catch (JDOMException e) {
			throw new AssertionError(e);
		}
	}

	private DebuggerTraceManagerServicePlugin traceManager;
	private DebuggerModelPlugin modelPlugin;

	record ObjHelp(TraceObject obj, Lifespan span, ConflictResolution resolution)
			implements AutoCloseable {
		@Override
		public void close() {
		}

		void value(String key, Object value) {
			obj.setValue(span, key, value);
		}

		ObjHelp child(String key) {
			TraceObject child =
				obj.getTrace().getObjectManager().createObject(obj.getCanonicalPath().extend(key));
			child.insert(span, resolution);
			return new ObjHelp(child, span, resolution);
		}
	}

	@Test
	public void testCaptureDebuggerModelPlugin() throws Throwable {
		traceManager = addPlugin(tool, DebuggerTraceManagerServicePlugin.class);
		modelPlugin = addPlugin(tool, DebuggerModelPlugin.class);

		DebuggerModelProvider provider = waitForComponentProvider(DebuggerModelProvider.class);

		var l = new Object() {
			TraceObject thread;
			TraceObject stack;
			TraceObject frame;
			TraceObject regs;
		};
		try (ToyDBTraceBuilder tb = new ToyDBTraceBuilder("bash", ProgramBuilder._TOY64_BE);
				Transaction tx = tb.startTransaction();) {
			DBTraceObjectManager om = tb.trace.getObjectManager();

			DBTraceObjectValue rootVal =
				om.createRootObject(CTX.getSchema(new SchemaName("Session")));

			try (ObjHelp root =
				new ObjHelp(rootVal.getChild(), Lifespan.nowOn(0), ConflictResolution.DENY)) {
				root.child("Available");
				try (ObjHelp processes = root.child("Processes")) {
					try (ObjHelp proc = processes.child("[0]")) {
						try (ObjHelp threads = proc.child("Threads")) {
							try (ObjHelp thread = threads.child("[0]")) {
								l.thread = thread.obj;
								try (ObjHelp stack = thread.child("Stack")) {
									l.stack = stack.obj;
									try (ObjHelp frame = stack.child("[0]")) {
										l.frame = frame.obj;
										frame.value("PC", tb.addr(0x00401234));
										l.regs = frame.child("Registers").obj;
									}
									try (ObjHelp frame = stack.child("[1]")) {
										frame.value("PC", tb.addr(0x00404321));
									}
								}
							}
						}
						proc.child("Breakpoints");
						proc.child("Memory");
						proc.child("Modules");
					}
				}
				root.value(TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME, l.thread);
			}

			traceManager.openTrace(tb.trace);
			traceManager.activateObject(l.frame);
			waitForTasks();

			provider.setTreeSelection(l.regs.getCanonicalPath());
			waitForTasks();
			provider.setTreeSelection(l.stack.getCanonicalPath());
			waitForTasks();

			List<ValueRow> frameRows = AbstractGhidraHeadedDebuggerTest.waitForPass(() -> {
				assertEquals(2, provider.elementsTablePanel.getAllItems().size());
				return provider.elementsTablePanel.getAllItems();
			});

			ValueRow frame0Row = frameRows.stream()
					.filter(r -> r.getValue().getValue() == l.frame)
					.findAny()
					.orElseThrow();
			provider.elementsTablePanel.setSelectedItem(frame0Row);
			waitForTasks();
		}

		captureIsolatedProvider(DebuggerModelProvider.class, 900, 900);
	}
}
