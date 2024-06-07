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
package ghidra.app.plugin.core.debug.gui.trace;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.core.debug.gui.AbstractGhidraHeadedDebuggerTest;
import ghidra.app.plugin.core.debug.gui.listing.*;
import ghidra.trace.database.ToyDBTraceBuilder;

public class DebuggerTraceTabPanelTest extends AbstractGhidraHeadedDebuggerTest {
	private DebuggerTraceTabPanel traceTabs;

	@Before
	public void setUpTabTest() throws Throwable {
		addPlugin(tool, DebuggerListingPlugin.class);
		DebuggerListingProvider listingProvider =
			waitForComponentProvider(DebuggerListingProvider.class);
		traceTabs = DebuggerListingProviderTestAccess.getTraceTabs(listingProvider);
	}

	@Test
	public void testEmpty() {
		assertEquals(List.of(), traceTabs.getTabValues());
	}

	@Test
	public void testOpenTraceAddsTab() throws Throwable {
		createAndOpenTrace();
		waitForSwing();

		assertEquals(List.of(tb.trace), traceTabs.getTabValues());
	}

	@Test
	public void testActivateTraceSelectsTab() throws Throwable {
		try (
				ToyDBTraceBuilder tb1 = new ToyDBTraceBuilder(getName() + "_1", LANGID_TOYBE64);
				ToyDBTraceBuilder tb2 = new ToyDBTraceBuilder(getName() + "_2", LANGID_TOYBE64)) {
			traceManager.openTrace(tb1.trace);
			traceManager.openTrace(tb2.trace);
			waitForSwing();

			traceManager.activateTrace(tb1.trace);
			waitForSwing();
			assertEquals(tb1.trace, traceTabs.getSelectedTabValue());

			traceManager.activateTrace(tb2.trace);
			waitForSwing();
			assertEquals(tb2.trace, traceTabs.getSelectedTabValue());
		}
	}

	@Test
	public void testSelectTabActivatesTrace() throws Throwable {
		try (
				ToyDBTraceBuilder tb1 = new ToyDBTraceBuilder(getName() + "_1", LANGID_TOYBE64);
				ToyDBTraceBuilder tb2 = new ToyDBTraceBuilder(getName() + "_2", LANGID_TOYBE64)) {
			traceManager.openTrace(tb1.trace);
			traceManager.openTrace(tb2.trace);
			waitForSwing();

			traceTabs.selectTab(tb1.trace);
			waitForSwing();
			assertEquals(tb1.trace, traceManager.getCurrentTrace());

			traceTabs.selectTab(tb2.trace);
			waitForSwing();
			assertEquals(tb2.trace, traceManager.getCurrentTrace());
		}
	}

	@Test
	public void testCloseTraceRemovesTab() throws Throwable {
		try (
				ToyDBTraceBuilder tb1 = new ToyDBTraceBuilder(getName() + "_1", LANGID_TOYBE64);
				ToyDBTraceBuilder tb2 = new ToyDBTraceBuilder(getName() + "_2", LANGID_TOYBE64)) {
			traceManager.openTrace(tb1.trace);
			traceManager.openTrace(tb2.trace);
			waitForSwing();

			assertEquals(List.of(tb1.trace, tb2.trace), traceTabs.getTabValues());

			traceManager.closeTrace(tb1.trace);
			waitForSwing();
			assertEquals(List.of(tb2.trace), traceTabs.getTabValues());

			traceManager.closeTrace(tb2.trace);
			waitForSwing();
			assertEquals(List.of(), traceTabs.getTabValues());
		}
	}
}
