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
package help.screenshot;

import java.awt.Rectangle;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import docking.DialogComponentProvider;
import docking.action.DockingActionIf;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.functioncompare.*;
import ghidra.app.util.viewer.listingpanel.ListingCodeComparisonPanel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class FunctionComparisonScreenShots extends GhidraScreenShotGenerator {

	private static final String TEST_SOURCE_PROGRAM_NAME = "VersionTracking/WallaceSrc";
	private static final String TEST_DESTINATION_PROGRAM_NAME = "VersionTracking/WallaceVersion2";

	private FunctionComparisonPlugin plugin;
	private Program sourceProgram;
	private Program destinationProgram;

	public FunctionComparisonScreenShots() {
		super();
	}

	@Override
	public void setUp() throws Exception {
		super.setUp();
		plugin = getPlugin(tool, FunctionComparisonPlugin.class);

		destinationProgram = loadProgram(TEST_DESTINATION_PROGRAM_NAME);
		sourceProgram = loadProgram(TEST_SOURCE_PROGRAM_NAME);
	}

	public void tearDown() throws Exception {
		super.tearDown();
	}

	@Test
	public void testFunctionComparisonWindow() {

		positionListingTop(0x004118f0);
		int txId1 = sourceProgram.startTransaction("Modify Program1");
		int txId2 = destinationProgram.startTransaction("Modify Program2");
		try {
			sourceProgram.getDomainFile().setName("FirstProgram");
			destinationProgram.getDomainFile().setName("SecondProgram");
			sourceProgram.setName("FirstProgram");
			destinationProgram.setName("SecondProgram");

			Listing sourceListing = sourceProgram.getListing();
			Listing destListing = destinationProgram.getListing();
			Memory sourceMemory = sourceProgram.getMemory();

			Function f1 = getFunction(sourceProgram, addr(0x004118f0));
			f1.setName("FunctionA", SourceType.USER_DEFINED);
			sourceListing.setComment(addr(0x004118f0), CodeUnit.PLATE_COMMENT, null);
			sourceListing.clearCodeUnits(addr(0x004119b1), addr(0x004119b4), false);
			sourceMemory.setByte(addr(0x004119b2), (byte) 0x55);
			sourceMemory.setByte(addr(0x004119b4), (byte) 0x52);
			disassemble(sourceProgram, 0x004119b1, 4, false);

			Function f2 = getFunction(destinationProgram, addr(0x004118c0));
			f2.setName("FunctionB", SourceType.USER_DEFINED);
			destListing.setComment(addr(0x004118c0), CodeUnit.PLATE_COMMENT, null);

			FunctionComparisonProviderManager providerMgr =
				getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
			FunctionComparisonProvider functionComparisonProvider =
				providerMgr.compareFunctions(f1, f2);
			FunctionComparisonPanel functionComparisonPanel =
				functionComparisonProvider.getComponent();
			runSwing(() -> {
				functionComparisonPanel.setCurrentTabbedComponent("Listing View");
				ListingCodeComparisonPanel dualListing =
					(ListingCodeComparisonPanel) functionComparisonPanel.getDisplayedPanel();
				ListingPanel leftPanel = dualListing.getLeftPanel();
				leftPanel.goTo(addr(0x004119aa));
			});
			waitForSwing();
			captureIsolatedProvider(FunctionComparisonProvider.class, 1200, 550);
		}
		catch (DuplicateNameException | InvalidInputException | MemoryAccessException
				| InvalidNameException | IOException e) {
			e.printStackTrace();
		}
		finally {
			destinationProgram.endTransaction(txId2, false);
			sourceProgram.endTransaction(txId1, false);
		}
	}

	@Test
	public void testAddToComparisonIcon() {
		Function f1 = getFunction(sourceProgram, addr(0x004118f0));
		Function f2 = getFunction(destinationProgram, addr(0x004118c0));

		FunctionComparisonProviderManager providerMgr =
			getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
		FunctionComparisonProvider functionComparisonProvider =
			providerMgr.compareFunctions(f1, f2);

		waitForSwing();

		captureProvider(functionComparisonProvider);
		crop(new Rectangle(261, 2, 24, 24));
	}

	@Test
	public void testRemoveFromComparisonIcon() {
		Function f1 = getFunction(sourceProgram, addr(0x004118f0));
		Function f2 = getFunction(destinationProgram, addr(0x004118c0));

		FunctionComparisonProviderManager providerMgr =
			getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
		FunctionComparisonProvider functionComparisonProvider =
			providerMgr.compareFunctions(f1, f2);

		waitForSwing();

		captureProvider(functionComparisonProvider);
		crop(new Rectangle(351, 2, 24, 24));
	}

	@Test
	public void testNavNextIcon() {
		Function f1 = getFunction(sourceProgram, addr(0x004118f0));
		Function f2 = getFunction(destinationProgram, addr(0x004118c0));

		FunctionComparisonProviderManager providerMgr =
			getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
		Set<Function> functions = new HashSet<>();
		functions.add(f1);
		functions.add(f2);
		FunctionComparisonProvider functionComparisonProvider =
			providerMgr.compareFunctions(functions);

		waitForSwing();

		captureProvider(functionComparisonProvider);
		crop(new Rectangle(293, 2, 24, 24));
	}

	@Test
	public void testNavPreviousIcon() {
		Function f1 = getFunction(sourceProgram, addr(0x004118f0));
		Function f2 = getFunction(destinationProgram, addr(0x004118c0));

		FunctionComparisonProviderManager providerMgr =
			getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
		Set<Function> functions = new HashSet<>();
		functions.add(f1);
		functions.add(f2);
		FunctionComparisonProvider functionComparisonProvider =
			providerMgr.compareFunctions(functions);
		MultiFunctionComparisonPanel panel =
			(MultiFunctionComparisonPanel) functionComparisonProvider.getComponent();
		panel.getFocusedComponent().setSelectedIndex(1);

		waitForSwing();

		captureProvider(functionComparisonProvider);
		crop(new Rectangle(315, 2, 24, 24));
	}

	@Test
	public void testAddFunctionsPanel() {
		Function f1 = getFunction(sourceProgram, addr(0x004118f0));
		Function f2 = getFunction(destinationProgram, addr(0x004118c0));

		FunctionComparisonProviderManager providerMgr =
			getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
		Set<Function> functions = new HashSet<>();
		functions.add(f1);
		functions.add(f2);
		providerMgr.compareFunctions(functions);

		DockingActionIf openTableAction = getAction(plugin, "Add Functions To Comparison");
		performAction(openTableAction);
		DialogComponentProvider table = waitForDialogComponent("Select Functions");
		captureDialog(table);
	}

	private Function getFunction(Program program1, Address entryPoint) {
		FunctionManager functionManager = program1.getFunctionManager();
		return functionManager.getFunctionAt(entryPoint);
	}

	private void disassemble(Program pgm1, long addressAsLong, int length, boolean followFlows) {
		Address address = addr(addressAsLong);
		DisassembleCommand cmd = new DisassembleCommand(address,
			new AddressSet(address, address.add(length - 1)), followFlows);
		cmd.applyTo(pgm1);
	}
}
