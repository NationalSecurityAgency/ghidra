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

import java.util.HashMap;
import java.util.HashSet;

import org.junit.Test;

import docking.ComponentProvider;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.functioncompare.*;
import ghidra.app.util.viewer.listingpanel.ListingCodeComparisonPanel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
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
	}

	@Test
	public void testFunctionComparisonWindow() {
		destinationProgram = loadProgram(TEST_DESTINATION_PROGRAM_NAME);
		sourceProgram = loadProgram(TEST_SOURCE_PROGRAM_NAME);

		positionListingTop(0x004118f0);
		int txId1 = sourceProgram.startTransaction("Modify Program1");
		int txId2 = destinationProgram.startTransaction("Modify Program2");
		try {
			sourceProgram.setName("TestProgram");
			destinationProgram.setName("OtherProgram");
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

			Function[] functions = new Function[] { f1, f2 };
			FunctionComparisonProviderManager providerMgr =
				getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
			FunctionComparisonProvider functionComparisonProvider =
				providerMgr.showFunctionComparisonProvider(functions);
			FunctionComparisonPanel functionComparisonPanel =
				functionComparisonProvider.getComponent();
			runSwing(() -> {
				functionComparisonPanel.setCurrentTabbedComponent("Listing View");
				ListingCodeComparisonPanel dualListing =
					(ListingCodeComparisonPanel) functionComparisonPanel.getDisplayedPanel();
				ListingPanel leftPanel = dualListing.getLeftPanel();
				dualListing.setLeftTitle("FunctionA() in /TestProgram");
				dualListing.setRightTitle("FunctionB() in /OtherProgram");
				leftPanel.goTo(addr(0x004119aa));

			});
			waitForSwing();
			captureIsolatedProvider(FunctionComparisonProvider.class, 1200, 550);
		}
		catch (DuplicateNameException e) {
			e.printStackTrace();
		}
		catch (InvalidInputException e) {
			e.printStackTrace();
		}
		catch (MemoryAccessException e) {
			e.printStackTrace();
		}
		finally {
			destinationProgram.endTransaction(txId2, false);
			sourceProgram.endTransaction(txId1, false);
		}
	}

	@Test
	public void testFunctionComparisonWindowFromMap() throws CircularDependencyException {
		destinationProgram = loadProgram(TEST_DESTINATION_PROGRAM_NAME);
		sourceProgram = loadProgram(TEST_SOURCE_PROGRAM_NAME);

		positionListingTop(0x004118f0);
		int txId1 = sourceProgram.startTransaction("Modify Program1");
		int txId2 = destinationProgram.startTransaction("Modify Program2");
		try {
			sourceProgram.setName("TestProgram");
			destinationProgram.setName("OtherProgram");
			Listing sourceListing = sourceProgram.getListing();
			Listing destListing = destinationProgram.getListing();
			Memory sourceMemory = sourceProgram.getMemory();

			Function f1 = getFunction(sourceProgram, addr(0x004118f0));
			f1.setName("Function1", SourceType.USER_DEFINED);
			Namespace parentNamespace = sourceProgram.getSymbolTable().createNameSpace(
				program.getGlobalNamespace(), "Namespace1", SourceType.USER_DEFINED);
			f1.setParentNamespace(parentNamespace);
			sourceListing.setComment(addr(0x004118f0), CodeUnit.PLATE_COMMENT, null);
			sourceListing.clearCodeUnits(addr(0x004119b1), addr(0x004119b4), false);
			sourceMemory.setByte(addr(0x004119b2), (byte) 0x55);
			sourceMemory.setByte(addr(0x004119b4), (byte) 0x52);
			disassemble(sourceProgram, 0x004119b1, 4, false);

			Function f2 = getFunction(destinationProgram, addr(0x004118c0));
			f2.setName("Function2", SourceType.USER_DEFINED);
			destListing.setComment(addr(0x004118c0), CodeUnit.PLATE_COMMENT, null);

			Function fA = getFunction(sourceProgram, addr(0x00411a30));
			fA.setName("FunctionA", SourceType.USER_DEFINED);
			sourceListing.setComment(addr(0x00411a30), CodeUnit.PLATE_COMMENT, null);

			Function fB = getFunction(destinationProgram, addr(0x00411a10));
			fB.setName("FunctionB", SourceType.USER_DEFINED);
			destListing.setComment(addr(0x00411a10), CodeUnit.PLATE_COMMENT, null);

			Function fC = getFunction(sourceProgram, addr(0x00411ab0));
			fC.setName("FunctionC", SourceType.USER_DEFINED);
			sourceListing.setComment(addr(0x00411ab0), CodeUnit.PLATE_COMMENT, null);

			Function fD = getFunction(destinationProgram, addr(0x00411a90));
			fD.setName("FunctionD", SourceType.USER_DEFINED);
			destListing.setComment(addr(0x00411a90), CodeUnit.PLATE_COMMENT, null);

			HashMap<Function, HashSet<Function>> functionMap = new HashMap<>();
			HashSet<Function> functionSet = new HashSet<>();
			functionSet.add(fA);
			functionSet.add(fB);
			functionMap.put(f1, functionSet);
			functionSet = new HashSet<>();
			functionSet.add(fC);
			functionSet.add(fD);
			functionMap.put(f2, functionSet);
			FunctionComparisonProviderManager providerMgr =
				getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
			FunctionComparisonProvider functionComparisonProvider =
				providerMgr.showFunctionComparisonProvider(functionMap);
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
		catch (DuplicateNameException | InvalidInputException | MemoryAccessException e) {
			e.printStackTrace();
		}
		finally {
			destinationProgram.endTransaction(txId2, false);
			sourceProgram.endTransaction(txId1, false);
		}
	}

	@Test
	public void testListingCodeComparisonOptions() {
		destinationProgram = loadProgram(TEST_DESTINATION_PROGRAM_NAME);
		sourceProgram = loadProgram(TEST_SOURCE_PROGRAM_NAME);

		positionListingTop(0x004118f0);
		int txId1 = sourceProgram.startTransaction("Modify Program1");
		int txId2 = destinationProgram.startTransaction("Modify Program2");
		try {
			sourceProgram.setName("TestProgram");
			destinationProgram.setName("OtherProgram");
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

			Function[] functions = new Function[] { f1, f2 };
			FunctionComparisonProviderManager providerMgr =
				getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
			FunctionComparisonProvider functionComparisonProvider =
				providerMgr.showFunctionComparisonProvider(functions);
			FunctionComparisonPanel functionComparisonPanel =
				functionComparisonProvider.getComponent();
			runSwing(() -> {
				functionComparisonPanel.setCurrentTabbedComponent("Listing View");
			});
			waitForSwing();

			ComponentProvider provider = getProvider("Function Comparison");
			performAction("Listing Code Comparison Options", "Function Comparison", provider,
				false);

			captureDialog(600, 300);
			pressButtonByText(getDialog(), "Cancel");

			waitForSwing();
		}
		catch (DuplicateNameException e) {
			e.printStackTrace();
		}
		catch (InvalidInputException e) {
			e.printStackTrace();
		}
		catch (MemoryAccessException e) {
			e.printStackTrace();
		}
		finally {
			destinationProgram.endTransaction(txId2, false);
			sourceProgram.endTransaction(txId1, false);
		}
	}

	@Test
	public void testMultiFunctionComparisonWindow() {
		destinationProgram = loadProgram(TEST_DESTINATION_PROGRAM_NAME);
		sourceProgram = loadProgram(TEST_SOURCE_PROGRAM_NAME);

		positionListingTop(0x004118f0);
		int txId1 = sourceProgram.startTransaction("Modify Program1");
		int txId2 = destinationProgram.startTransaction("Modify Program2");
		try {
			sourceProgram.setName("TestProgram");
			destinationProgram.setName("OtherProgram");
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

			Function f3 = getFunction(sourceProgram, addr(0x004117c0));
			f3.setName("FunctionC", SourceType.USER_DEFINED);
			sourceListing.setComment(addr(0x004117c0), CodeUnit.PLATE_COMMENT, null);

			Function f4 = getFunction(destinationProgram, addr(0x004117b0));
			f4.setName("FunctionD", SourceType.USER_DEFINED);
			destListing.setComment(addr(0x004117b0), CodeUnit.PLATE_COMMENT, null);

			Function[] functions = new Function[] { f1, f2, f3, f4 };
			FunctionComparisonProviderManager providerMgr =
				getInstanceFieldByClassType(FunctionComparisonProviderManager.class, plugin);
			FunctionComparisonProvider functionComparisonProvider =
				providerMgr.showFunctionComparisonProvider(functions);
			FunctionComparisonPanel functionComparisonPanel =
				functionComparisonProvider.getComponent();
			runSwing(() -> {
				functionComparisonPanel.setCurrentTabbedComponent("Listing View");
				ListingCodeComparisonPanel dualListing =
					(ListingCodeComparisonPanel) functionComparisonPanel.getDisplayedPanel();
				ListingPanel leftPanel = dualListing.getLeftPanel();
				leftPanel.goTo(addr(0x004119a5));

			});
			waitForSwing();
			captureIsolatedProvider(FunctionComparisonProvider.class, 1200, 598);
		}
		catch (DuplicateNameException | InvalidInputException | MemoryAccessException e) {
			e.printStackTrace();
		}
		finally {
			destinationProgram.endTransaction(txId2, false);
			sourceProgram.endTransaction(txId1, false);
		}
	}

	Function getFunction(Program program1, Address entryPoint) {
		FunctionManager functionManager = program1.getFunctionManager();
		return functionManager.getFunctionAt(entryPoint);
	}

	public void disassemble(Program pgm1, long addressAsLong, int length, boolean followFlows) {
		Address address = addr(addressAsLong);
		DisassembleCommand cmd = new DisassembleCommand(address,
			new AddressSet(address, address.add(length - 1)), followFlows);
		cmd.applyTo(pgm1);
	}
}
