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
package ghidra.app.plugin.core.debug.gui.register;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Test;

import db.Transaction;
import ghidra.debug.api.control.ControlMode;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.data.DoubleDataType;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceObjectThread;

public class DebuggerRmiRegistersProviderTest extends AbstractDebuggerRegistersProviderTest {

	protected TraceObject setUpRmiTarget() throws Throwable {
		createRmiConnection();
		addRegisterMethods();
		createTrace();
		try (Transaction tx = tb.startTransaction()) {
			tb.trace.getObjectManager().createRootObject(SCHEMA_SESSION);
			tb.createObjectsProcessAndThreads();
			tb.createObjectsFramesAndRegs(
				tb.obj("Processes[1].Threads[1]").queryInterface(TraceObjectThread.class),
				Lifespan.nowOn(0), tb.host, 2);
		}
		rmiCx.publishTarget(tool, tb.trace);
		traceManager.openTrace(tb.trace);
		traceManager.activateTrace(tb.trace);
		return Objects.requireNonNull(tb.obj("Processes[1]"));
	}

	protected void handleReadRegsInvocation(TraceObject container) throws Throwable {
		Map<String, Object> args = rmiMethodReadRegs.expect();
		rmiMethodReadRegs.result(null);
		assertEquals(Map.ofEntries(
			Map.entry("container", container)),
			args);
	}

	protected void handleWriteRegInvocation(TraceObjectStackFrame frame, String name, long value)
			throws Throwable {
		Map<String, Object> args = rmiMethodWriteReg.expect();
		rmiMethodWriteReg.result(null);
		assertEquals(Set.of("frame", "name", "value"), args.keySet());
		assertEquals(frame.getObject(), args.get("frame"));
		assertEquals("r0", args.get("name"));
		assertEquals(value, Utils.bytesToLong((byte[]) args.get("value"), 8, true));
	}

	@Test
	public void testReadLiveValuesOnActivate() throws Throwable {
		setUpRmiTarget();
		waitForSwing();

		handleReadRegsInvocation(tb.obj("Processes[1].Threads[1].Stack[0].Registers"));
	}

	@Test
	public void testModifyValueLive() throws Throwable {
		setUpRmiTarget();
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);

		assertTrue(registersProvider.actionEnableEdits.isEnabled());
		performAction(registersProvider.actionEnableEdits);

		RegisterRow row = findRegisterRow(r0);

		setRowText(row, "1234");
		handleWriteRegInvocation(
			tb.obj("Processes[1].Threads[1].Stack[0]").queryInterface(TraceObjectStackFrame.class),
			"r0", 0x1234);
	}

	@Test
	public void testModifyRepresentationLive() throws Throwable {
		setUpRmiTarget();
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);

		assertTrue(registersProvider.actionEnableEdits.isEnabled());
		performAction(registersProvider.actionEnableEdits);

		RegisterRow row = findRegisterRow(r0);
		assertFalse(row.isRepresentationEditable());

		row.setDataType(DoubleDataType.dataType);
		waitForDomainObject(tb.trace);

		setRowRepr(row, "1234");
		handleWriteRegInvocation(
			tb.obj("Processes[1].Threads[1].Stack[0]").queryInterface(TraceObjectStackFrame.class),
			"r0", encodeDouble(1234));
	}
}
