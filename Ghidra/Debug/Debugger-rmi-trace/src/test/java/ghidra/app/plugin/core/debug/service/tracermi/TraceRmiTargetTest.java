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
package ghidra.app.plugin.core.debug.service.tracermi;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiTarget.FoundRegister;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracermi.TraceRmiConnection;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.Register;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.schema.SchemaContext;
import ghidra.trace.model.target.schema.XmlSchemaContext;
import ghidra.trace.model.thread.TraceThread;

public class TraceRmiTargetTest extends AbstractGhidraHeadedDebuggerTest {

	class MyTraceRmiConnection extends TestTraceRmiConnection {

		@Override
		protected DebuggerTraceManagerService getTraceManager() {
			return null;
		}

		@Override
		protected DebuggerControlService getControlService() {
			return null;
		}
	}

	@Test
	public void testSearchForRegistersInGroups() throws Exception {
		SchemaContext ctx = XmlSchemaContext.deserialize("""
				<context>
				    <schema name="root">
				        <interface name="Aggregate" />
				        <attribute name="Threads" schema="ThreadContainer" />
				    </schema>
				    <schema name="ThreadContainer" canonical="yes">
				        <element schema="Thread" />
				    </schema>
				    <schema name="Thread">
				        <interface name="Thread" />
				        <interface name="Aggregate" />
				        <attribute name="Registers" schema="RegisterValueContainer" />
				    </schema>
				    <schema name="RegisterValueContainer">
				        <interface name="RegisterContainer" />
				        <attribute name="General Purpose" schema="RegisterBank" />
				    </schema>
				    <schema name="RegisterBank" canonical="yes">
				        <attribute schema="Register" />
				        <interface name="Aggregate" />
				    </schema>
				    <schema name="Register">
				        <interface name="Register" />
				    </schema>
				</context>
				""");

		PluginTool tool = env.getTool();
		createTrace("x86:LE:64:default");
		Register regRax = tb.reg("RAX");
		try (Transaction tx = tb.startTransaction()) {
			tb.createRootObject(ctx, "root");
			TraceObject objRax = tb.trace.getObjectManager()
					.createObject(KeyPath.parse("Threads[1].Registers.General Purpose.RAX"));
			objRax.insert(Lifespan.ALL, ConflictResolution.DENY);
		}

		try (TraceRmiConnection cx = new MyTraceRmiConnection()) {
			TraceRmiTarget target = new TraceRmiTarget(tool, cx, tb.trace);

			TraceThread thread = tb.obj("Threads[1]").queryInterface(TraceThread.class);
			FoundRegister found = target.findRegister(thread, 0, regRax);
			assertEquals("Threads[1].Registers.General Purpose.RAX",
				found.value().getCanonicalPath().toString());
		}
	}

}
