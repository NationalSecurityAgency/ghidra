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

import org.junit.Test;
import org.junit.experimental.categories.Category;

import generic.test.category.NightlyCategory;
import ghidra.debug.api.control.ControlMode;
import ghidra.debug.api.model.TraceRecorder;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.data.DoubleDataType;

@Category(NightlyCategory.class)
public class DebuggerRecorderRegistersProviderTest extends AbstractDebuggerRegistersProviderTest {

	@Test
	public void testLiveAddValuesThenActivatePopulatesPanel() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(recorder.getTrace());
		waitForSwing();

		mb.testBank1.writeRegister("pc", new byte[] { 0x00, 0x40, 0x00, 0x00 });
		waitForSwing();

		activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		assertPCRowValuePopulated();
	}

	@Test
	public void testLiveActivateThenAddValuesPopulatesPanel() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(recorder.getTrace());
		activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		mb.testBank1.writeRegister("pc", new byte[] { 0x00, 0x40, 0x00, 0x00 });
		waitRecorder(recorder);

		RegisterRow rowL = findRegisterRow(pc);
		waitForPass(() -> assertTrue(rowL.isKnown()));
		assertPCRowValuePopulated();
	}

	@Test
	public void testModifyValueLive() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(recorder.getTrace());
		activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);

		assertTrue(registersProvider.actionEnableEdits.isEnabled());
		performAction(registersProvider.actionEnableEdits);

		RegisterRow row = findRegisterRow(r0);

		setRowText(row, "1234");
		waitRecorder(recorder);
		assertArrayEquals(new byte[] { 0, 0, 0, 0, 0, 0, 0x12, 0x34 },
			mb.testBank1.regVals.get("r0"));
	}

	@Test
	public void testModifyRepresentationLive() throws Throwable {
		TraceRecorder recorder = recordAndWaitSync();
		traceManager.openTrace(recorder.getTrace());
		activateThread(recorder.getTraceThread(mb.testThread1));
		waitForSwing();

		controlService.setCurrentMode(tb.trace, ControlMode.RW_TARGET);

		assertTrue(registersProvider.actionEnableEdits.isEnabled());
		performAction(registersProvider.actionEnableEdits);

		RegisterRow row = findRegisterRow(r0);
		assertFalse(row.isRepresentationEditable());

		row.setDataType(DoubleDataType.dataType);
		waitForDomainObject(tb.trace);

		setRowRepr(row, "1234");
		waitRecorder(recorder);
		assertEquals(encodeDouble(1234),
			Utils.bytesToLong(mb.testBank1.regVals.get("r0"), 8, true));
	}
}
