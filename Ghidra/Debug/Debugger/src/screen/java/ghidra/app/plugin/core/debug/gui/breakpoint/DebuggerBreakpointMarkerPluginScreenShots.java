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
package ghidra.app.plugin.core.debug.gui.breakpoint;

import java.awt.event.MouseEvent;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import generic.Unique;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import help.screenshot.GhidraScreenShotGenerator;

public class DebuggerBreakpointMarkerPluginScreenShots extends GhidraScreenShotGenerator {
	DebuggerLogicalBreakpointService breakpointService;
	DebuggerBreakpointMarkerPlugin breakpointMarkerPlugin;
	ProgramManager programManager;

	CodeViewerProvider listing;

	Program program;

	protected static Address addr(Program program, long offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	@Before
	public void setUpMine() throws Exception {
		breakpointService = addPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		breakpointMarkerPlugin = addPlugin(tool, DebuggerBreakpointMarkerPlugin.class);
		programManager = addPlugin(tool, ProgramManagerPlugin.class);

		listing = waitForComponentProvider(CodeViewerProvider.class);

		program = programManager.getCurrentProgram();
	}

	@Test
	public void testCaptureDebuggerBreakpointMarkerPlugin() throws Throwable {
		ListingPanel panel = listing.getListingPanel();

		tool.getProject()
				.getProjectData()
				.getRootFolder()
				.createFile("WinHelloCPP", program, TaskMonitor.DUMMY);

		Msg.debug(this, "Placing breakpoint");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401c60), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE));

		Msg.debug(this, "Disabling breakpoint");
		LogicalBreakpoint lb = waitForValue(() -> Unique.assertAtMostOne(
			breakpointService.getBreakpointsAt(program, addr(program, 0x00401c60))));
		lb.disable();

		Msg.debug(this, "Placing another");
		breakpointService.placeBreakpointAt(program, addr(program, 0x00401c63), 1,
			Set.of(TraceBreakpointKind.SW_EXECUTE));

		Msg.debug(this, "Saving program");
		program.save("Placed breakpoints", TaskMonitor.DUMMY);

		Msg.debug(this, "Clicking and capturing");
		DebuggerBreakpointMarkerPluginTest.clickListing(panel, addr(program, 0x00401c66),
			MouseEvent.BUTTON3);
		waitForSwing();

		captureProviderWithScreenShot(listing);
	}

	@Test
	public void testCaptureDebuggerPlaceBreakpointDialog() throws Throwable {
		listing.goTo(program, new ProgramLocation(program, addr(program, 0x00401c63)));
		performAction(breakpointMarkerPlugin.actionSetSoftwareBreakpoint, false);

		captureDialog(DebuggerPlaceBreakpointDialog.class);
	}
}
