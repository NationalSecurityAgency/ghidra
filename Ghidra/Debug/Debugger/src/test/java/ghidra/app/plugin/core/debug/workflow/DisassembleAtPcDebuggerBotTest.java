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
package ghidra.app.plugin.core.debug.workflow;

import static org.junit.Assert.*;

import java.util.Set;
import java.util.stream.Collectors;

import org.junit.Before;
import org.junit.Test;

import com.google.common.collect.Range;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerGUITest;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingPlugin;
import ghidra.app.plugin.core.debug.service.platform.DebuggerPlatformServicePlugin;
import ghidra.app.plugin.core.debug.service.workflow.DebuggerWorkflowServiceProxyPlugin;
import ghidra.app.services.DebuggerBot;
import ghidra.app.services.DebuggerWorkflowService;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.program.model.listing.Instruction;
import ghidra.trace.database.listing.DBTraceInstructionsMemoryView;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.model.memory.TraceMemoryFlag;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectKeyPath;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.util.database.UndoableTransaction;

public class DisassembleAtPcDebuggerBotTest extends AbstractGhidraHeadedDebuggerGUITest {
	protected SchemaContext ctx;

	@Before
	public void setUpDisassembleAtPcTest() throws Exception {
		ctx = XmlSchemaContext.deserialize("" + //
			"<context>" + //
			"    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>" + //
			"        <attribute name='Targets' schema='TargetContainer' />" + //
			"    </schema>" + //
			"    <schema name='TargetContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='ONCE'>" + //
			"        <element schema='Target' />" + //
			"    </schema>" + //
			"    <schema name='Target' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='Process' />" + //
			"        <interface name='Aggregate' />" + //
			"        <attribute name='Environment' schema='Environment' />" + //
			"        <attribute name='Memory' schema='Memory' />" + //
			"        <attribute name='Threads' schema='ThreadContainer' />" + //
			"    </schema>" + //
			"    <schema name='Environment' elementResync='NEVER' " + //
			"            attributeResync='NEVER'>" + //
			"        <interface name='Environment' />" + //
			"    </schema>" + //
			"    <schema name='Memory' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='NEVER'>" + //
			"        <element schema='MemoryRegion' />" + //
			"    </schema>" + //
			"    <schema name='MemoryRegion' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='MemoryRegion' />" + //
			"    </schema>" + //
			"    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='NEVER'>" + //
			"        <element schema='Thread' />" + //
			"    </schema>" + //
			"    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='Thread' />" + //
			"        <interface name='Aggregate' />" + //
			"        <attribute name='Stack' schema='Stack' />" + //
			"    </schema>" + //
			"    <schema name='Stack' canonical='yes' elementResync='NEVER' " + //
			"            attributeResync='NEVER'>" + //
			"        <interface name='Stack' />" + //
			"        <element schema='Frame' />" + //
			"    </schema>" + //
			"    <schema name='Frame' elementResync='NEVER' attributeResync='NEVER'>" + //
			"        <interface name='StackFrame' />" + //
			"    </schema>" + //
			"</context>");

		DebuggerWorkflowService workflowService =
			addPlugin(tool, DebuggerWorkflowServiceProxyPlugin.class);
		addPlugin(tool, DebuggerListingPlugin.class);
		addPlugin(tool, DebuggerPlatformServicePlugin.class);

		Set<DebuggerBot> disBot = workflowService.getAllBots()
				.stream()
				.filter(b -> b instanceof DisassembleAtPcDebuggerBot)
				.collect(Collectors.toSet());
		assertEquals(1, disBot.size());
		workflowService.enableBots(disBot);
	}

	protected void assertX86Nop(Instruction instruction) {
		assertNotNull(instruction);
		assertEquals("NOP", instruction.getMnemonicString());
	}

	@Test
	public void testDisassembleX8664() throws Throwable {
		createAndOpenTrace("DATA:BE:64:default");

		DBTraceObjectManager objects = tb.trace.getObjectManager();
		try (UndoableTransaction tid = tb.startTransaction()) {
			objects.createRootObject(ctx.getSchema(new SchemaName("Session")));
			DBTraceObject env =
				objects.createObject(TraceObjectKeyPath.parse("Targets[0].Environment"));
			assertEquals(ctx.getSchema(new SchemaName("Environment")), env.getTargetSchema());
			Range<Long> zeroOn = Range.atLeast(0L);
			env.insert(zeroOn, ConflictResolution.DENY);
			env.setAttribute(zeroOn, TargetEnvironment.DEBUGGER_ATTRIBUTE_NAME, "test");
			env.setAttribute(zeroOn, TargetEnvironment.ARCH_ATTRIBUTE_NAME, "x86-64");

			DBTraceObject objBinText =
				objects.createObject(TraceObjectKeyPath.parse("Targets[0].Memory[bin:.text]"));
			TraceObjectMemoryRegion binText =
				objBinText.queryInterface(TraceObjectMemoryRegion.class);
			binText.addFlags(zeroOn, Set.of(TraceMemoryFlag.EXECUTE));
			binText.setRange(zeroOn, tb.range(0x00400000, 0x0040ffff));
			// TODO: Why doesn't setRange work after insert?
			objBinText.insert(zeroOn, ConflictResolution.DENY);

			DBTraceObject objFrame =
				objects.createObject(TraceObjectKeyPath.parse("Targets[0].Threads[0].Stack[0]"));
			objFrame.insert(zeroOn, ConflictResolution.DENY);
			TraceObjectStackFrame frame = objFrame.queryInterface(TraceObjectStackFrame.class);
			frame.setProgramCounter(zeroOn, tb.addr(0x00400000));

			DBTraceMemoryManager memory = tb.trace.getMemoryManager();
			memory.putBytes(0, tb.addr(0x00400000), tb.buf(0x90, 0x90, 0x90));
		}
		TraceObjectThread thread =
			objects.getObjectByCanonicalPath(TraceObjectKeyPath.parse("Targets[0].Threads[0]"))
					.queryInterface(TraceObjectThread.class);
		traceManager.activateThread(thread);

		getSLEIGH_X86_64_LANGUAGE(); // So that the load isn't charged against the time-out

		waitForPass(() -> {
			DBTraceInstructionsMemoryView instructions = tb.trace.getCodeManager().instructions();
			assertX86Nop(instructions.getAt(0, tb.addr(0x00400000)));
			assertX86Nop(instructions.getAt(0, tb.addr(0x00400001)));
			assertX86Nop(instructions.getAt(0, tb.addr(0x00400002)));
			assertNull(instructions.getAt(0, tb.addr(0x00400003)));
		});
	}
}
