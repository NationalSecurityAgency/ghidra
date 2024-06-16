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

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.junit.Before;
import org.junit.experimental.categories.Category;

import db.Transaction;
import generic.test.category.NightlyCategory;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.thread.TraceThread;

@Category(NightlyCategory.class)
public class DebuggerGuestTraceRegistersProviderTest extends DebuggerTraceRegistersProviderTest {

	@Override
	protected void createTrace() throws IOException {
		createTrace("DATA:BE:64:default");
	}

	@Before
	@Override
	public void setUpRegistersProviderTest() throws Exception {
		setUpGuestRegistersProviderTest();
	}

	@Override
	protected TracePlatform getPlatform() {
		return toy;
	}

	@Override
	protected void activateThread(TraceThread thread) {
		traceManager.activate(traceManager.resolveThread(thread).platform(toy));
	}

	@Override
	protected void addRegisterValues(TraceThread thread, Transaction tx) {
		TraceMemorySpace regVals =
			tb.trace.getMemoryManager().getMemoryRegisterSpace(thread, true);
		regVals.putBytes(toy, 0, pc, tb.buf(0, 0, 0, 0, 0, 0x40, 0, 0));
		regVals.putBytes(toy, 0, sp, tb.buf(0x1f, 0, 0, 0, 0, 0, 0, 0));
		regVals.putBytes(toy, 0, r0, tb.buf(1, 2, 3, 4, 5, 6, 7, 8));
	}

	@Override
	public void testDefaultSelection() throws Exception {
		traceManager.openTrace(tb.trace);

		TraceThread thread = addThread();
		addRegisterValues(thread);
		traceManager.activate(traceManager.resolveThread(thread).platform(toy));
		waitForSwing();

		assertEquals(DebuggerRegistersProvider.collectCommonRegisters(toy.getCompilerSpec()),
			registersProvider.getSelectionFor(toy));
	}
}
