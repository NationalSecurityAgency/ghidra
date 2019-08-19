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
package ghidra.app.merge.listing;

import static org.junit.Assert.*;

import java.awt.*;
import java.math.BigInteger;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;

import org.junit.Assert;

import docking.DialogComponentProvider;
import docking.DockingDialog;
import docking.test.AbstractDockingTest;
import docking.widgets.dialogs.ReadTextDialog;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.FunctionStackAnalysisCmd;
import ghidra.app.merge.AbstractMergeTest;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.program.database.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Test the merge of the versioned program's listing.
 */
public abstract class AbstractListingMergeManagerTest extends AbstractMergeTest
		implements ListingMergeConstants {

	protected static final String LATEST_BUTTON = ListingMergeConstants.LATEST_BUTTON_NAME;
	protected static final String MY_BUTTON = ListingMergeConstants.CHECKED_OUT_BUTTON_NAME;
	protected static final String ORIGINAL_BUTTON = ListingMergeConstants.ORIGINAL_BUTTON_NAME;
	protected static final String LATEST_CHECK_BOX = ListingMergeConstants.LATEST_CHECK_BOX_NAME;
	protected static final String MY_CHECK_BOX = ListingMergeConstants.CHECKED_OUT_CHECK_BOX_NAME;
	protected static final String ORIGINAL_CHECK_BOX =
		ListingMergeConstants.ORIGINAL_CHECK_BOX_NAME;

	protected static final String REMOVE_LATEST_BUTTON =
		ListingMergeConstants.REMOVE_LATEST_BUTTON_NAME;
	protected static final String RENAME_LATEST_BUTTON =
		ListingMergeConstants.RENAME_LATEST_BUTTON_NAME;
	protected static final String REMOVE_MY_BUTTON =
		ListingMergeConstants.REMOVE_CHECKED_OUT_BUTTON_NAME;
	protected static final String RENAME_MY_BUTTON =
		ListingMergeConstants.RENAME_CHECKED_OUT_BUTTON_NAME;

	protected AddressFactory resultAddressFactory;
	protected ListingMergeManager listingMergeMgr;
	protected TaskMonitor monitor = TaskMonitor.DUMMY;

	protected Instruction createInstruction(Program program, Address atAddress) {

		int txID = program.startTransaction("Create Instruction");
		boolean commit = false;
		try {
			Listing listing = program.getListing();
			Memory memory = program.getMemory();
			MemBuffer buf = new DumbMemBufferImpl(memory, atAddress);
			ProcessorContext context =
				new ProgramProcessorContext(program.getProgramContext(), atAddress);
			InstructionPrototype proto = program.getLanguage().parse(buf, context, false);
			Instruction createdInstruction =
				listing.createInstruction(atAddress, proto, buf, context);
			commit = true;
			return createdInstruction;
		}
		catch (Exception e) {
			// Commit is false by default so nothing else to do.
			return null;
		}
		finally {
			program.endTransaction(txID, commit);
		}
	}

	/**
	 * This is a generic method for testing merge conflicts for equates on data. It sets the bytes 
	 * to those indicated beginning at the indicated address and then creates Data using the 
	 * specified data type at that address. It then creates a conflicting equate name and
	 * chooses the Latest or My change based on the boolean flag, chooseMy.
	 * @param address the address where the data is created
	 * @param dt the data type (determines the size of equate)
	 * @param bytes the bytes that determine the equate value.
	 * @param expectedValue the expected value for the equate as a long after merging the conflict.
	 * @param chooseMy true indicates to choose My changes, false for Latest changes.
	 * @throws Exception if test can't execute properly.
	 */
	protected void runTestAddNameDiffPickIndicated(String address, DataType dt, byte[] bytes,
			long expectedValue, boolean chooseMy) throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					Address addr = addr(program, address);
					try {
						program.getMemory().setBytes(addr, bytes);
						listing.createData(addr, dt);
					}
					catch (CodeUnitInsertionException | DataTypeConflictException
							| MemoryAccessException e) {
						Assert.fail(e.getMessage());
					}
					Data data = listing.getDataAt(addr);
					Assert.assertTrue(data != null);
					Assert.assertTrue(dt.isEquivalent(data.getDataType()));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, address);
					try {
						equateTab.createEquate("FOO", expectedValue).addReference(addr, 0);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					EquateTable equateTab = program.getEquateTable();
					Address addr = addr(program, address);
					try {
						equateTab.createEquate("BAR", expectedValue).addReference(addr, 0);
					}
					catch (DuplicateNameException | InvalidInputException e) {
						Assert.fail(e.getMessage());
					}
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseEquate(address, 0, (chooseMy ? KEEP_MY : KEEP_LATEST));
		waitForMergeCompletion();

		EquateTable equateTab = resultProgram.getEquateTable();
		List<Equate> equates = equateTab.getEquates(addr(address), 0);
		assertEquals(1, equates.size());
		Equate eq = equates.get(0);
		assertEquals((chooseMy ? "BAR" : "FOO"), eq.getName());
		assertEquals(expectedValue, eq.getValue());
	}

	protected static class MyParameter extends ParameterImpl {

		MyParameter(String name, int ordinal, DataType dt, int stackOffset, ProgramDB program)
				throws InvalidInputException {
			super(name, dt, stackOffset, program, SourceType.USER_DEFINED);
			this.ordinal = ordinal;
		}
	}

	Window waitForMergeCancelWindow(int waitMillis) {
		return waitForWindow("Confirm Cancel Merge");
	}

	void escapeActiveWindow() {
		Window activeWindow =
			KeyboardFocusManager.getCurrentKeyboardFocusManager().getActiveWindow();
		assertNotNull(activeWindow);
		waitForSwing();
		triggerEscapeKey(activeWindow);
	}

	void escapeWindowWithTitleContaining(String partOfTitle) {
		Window win = getWindowWithTitleContaining(partOfTitle);
		if (win != null) {
			waitForSwing();
			triggerEscapeKey(win);
		}
	}

	Window getWindowWithTitleContaining(String partOfTitle) {
		return AbstractDockingTest.getWindowByTitleContaining(null, partOfTitle);
	}

	/**
	 * Get the specified address from the result program of the version merge.
	 * @param address String indicating the address
	 * @return the address
	 */
	protected Address addr(String address) {
		return resultProgram.getAddressFactory().getAddress(address);
	}

	/**
	 * Get the specified address from the specified program of the version merge.
	 * @param pgm get the address from this program
	 * @param address String indicating the address
	 * @return the address
	 */
	protected Address addr(Program pgm, String address) {
		return pgm.getAddressFactory().getAddress(address);
	}

	void assertSameDataType(DataType dt1, DataType dt2) {
		assertTrue(
			"DataType '" + dt1.getDisplayName() + "' not same as '" + dt2.getDisplayName() + "'",
			dt1.isEquivalent(dt2));
	}

	/**
	 * Assert that the code units from the two indicated programs are the same
	 * for the addresses indicated by the address set.
	 * If not then a JUnit failure occurs.
	 * @param p1 first program
	 * @param p2 second program
	 * @param addrs address set where code units should be the same.
	 * @throws ProgramConflictException if the programs can't be compared.
	 */
	protected void assertSameCodeUnits(Program p1, Program p2, AddressSetView addrs)
			throws ProgramConflictException {
		ProgramDiff diff = new ProgramDiff(p1, p2, addrs);
		AddressSetView diffs;
		try {
			diffs = diff.getDifferences(new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS),
				TaskMonitor.DUMMY);
			assertTrue("Not same code units at " + diffs.toString(), diffs.isEmpty());
		}
		catch (CancelledException e) {
			throw new AssertException(e);
		}
	}

	protected void assertSameBytes(Program p1, Program p2, AddressSetView addrs)
			throws ProgramConflictException {
		ProgramDiff diff = new ProgramDiff(p1, p2, addrs);
		try {
			AddressSetView diffs = diff.getDifferences(
				new ProgramDiffFilter(ProgramDiffFilter.BYTE_DIFFS), TaskMonitor.DUMMY);
			assertTrue("Not same bytes at " + diffs.toString(), diffs.isEmpty());
		}
		catch (CancelledException e) {
			// Shouldn't happen
			failWithException(e.getMessage(), e);
		}
	}

	// **** Methods for manipulating Latest or Checked Out program. ****

	protected void clear(Program program, String minAddress, String maxAddress) {
		Address min = addr(program, minAddress);
		Address max = addr(program, maxAddress);
		program.getListing().clearCodeUnits(min, max, false);
	}

	protected void disassemble(Program program, String minAddress, String maxAddress) {
		Address min = addr(program, minAddress);
		Address max = addr(program, maxAddress);
		DisassembleCommand disCmd =
			new DisassembleCommand(min, program.getAddressFactory().getAddressSet(min, max), false);
		disCmd.applyTo(program);
	}

	protected void disassemble(Program program, AddressSet addrSet, boolean followFlow) {
		DisassembleCommand disCmd =
			new DisassembleCommand(addrSet.getMinAddress(), addrSet, followFlow);
		disCmd.applyTo(program);
	}

	protected void setContextReg(Program program, String minAddress, String maxAddress, long value)
			throws ContextChangeException {
		ProgramContext programContext = program.getProgramContext();
		Register contextReg = programContext.getBaseContextRegister();
		programContext.setRegisterValue(addr(program, minAddress), addr(program, maxAddress),
			new RegisterValue(contextReg, BigInteger.valueOf(value)));
	}

	protected void createData(Program program, String address, DataType dt) {
		try {
			program.getListing().createData(addr(program, address), dt);
		}
		catch (Exception e) {
			failWithException(e.getMessage(), e);
		}
	}

	protected void setBytes(ProgramDB program, String address, byte[] bs) {
		Address addr = program.getAddressFactory().getAddress(address);
		try {
			program.getMemory().setBytes(addr, bs);
		}
		catch (MemoryAccessException e) {
			Assert.fail(e.getMessage());
		}
	}

	protected void setEquate(ProgramDB program, String name, long value, String address,
			int opndPosition) {
		EquateTable et = program.getEquateTable();
		Equate equate = et.getEquate(name);
		if (equate == null) {
			try {
				equate = et.createEquate(name, value);
			}
			catch (Exception e) {
				Assert.fail(e.getMessage());
			}
		}
		Address addr = addr(program, address);
		if (equate != null) {
			equate.addReference(addr, opndPosition);
		}
	}

	protected void createFunction(ProgramDB program, String entryPoint, String name,
			AddressSetView body) {
		Address addr = addr(program, entryPoint);
		try {
			program.getFunctionManager().createFunction(name, addr, body, SourceType.USER_DEFINED);
		}
		catch (Exception e) {
			Assert.fail("Can't create function @ " + entryPoint + "\n" + e.getMessage());
		}
	}

	protected void createAnalyzedFunction(ProgramDB program, String entryPoint, String name) {
		Address addr = addr(program, entryPoint);
		try {
			CreateFunctionCmd functionCmd =
				new CreateFunctionCmd(name, addr, null, SourceType.ANALYSIS);
			assertTrue("Failed to create function " + name + " @ " + addr,
				functionCmd.applyTo(program));
			Function newFunction = program.getFunctionManager().getFunctionAt(addr);
			assertNotNull(newFunction);

			if (newFunction.isThunk()) {
				// TODO For thunk functions need to call thunk analyzer here before 
				// stack analysis occurs
			}
			FunctionStackAnalysisCmd analyzeCmd = new FunctionStackAnalysisCmd(addr, true);
			assertTrue("Failed to analyze stack for " + name + " @ " + addr,
				analyzeCmd.applyTo(program));
		}
		catch (Exception e) {
			failWithException("Can't create analyzed function @ " + entryPoint, e);
		}
	}

	protected void removeFunction(ProgramDB program, String entryPoint) {
		Address addr = addr(program, entryPoint);
		assertTrue("Can't remove function @ " + entryPoint,
			program.getFunctionManager().removeFunction(addr));
	}

	protected void executeMerge(int decision) throws Exception {
		executeMerge(decision, false);
	}

	protected ProgramMultiUserMergeManager createMergeManager(ProgramChangeSet resultChangeSet,
			ProgramChangeSet myChangeSet) {
		return new ProgramMultiUserMergeManager(resultProgram, myProgram, originalProgram,
			latestProgram, resultChangeSet, myChangeSet);
	}

	/**
	 * Starts the merge and sets "window" to the merge dialog.
	 * @param decision the conflict decision
	 * @param waitForVisibleWindow true to wait
	 * @throws Exception if the sleep for the automatic merge was interrupted.
	 */
	protected void executeMerge(int decision, boolean waitForVisibleWindow) throws Exception {
		originalProgram = mtf.getOriginalProgram();
		myProgram = mtf.getPrivateProgram();// my program
		resultProgram = mtf.getResultProgram();// destination program
		latestProgram = mtf.getLatestProgram();// latest version (results and latest start out the same);		
		resultAddressFactory = resultProgram.getAddressFactory();

		ProgramChangeSet resultChangeSet = mtf.getResultChangeSet();
		ProgramChangeSet myChangeSet = mtf.getPrivateChangeSet();
		mergeMgr = createMergeManager(resultChangeSet, myChangeSet);

		listingMergeMgr = (ListingMergeManager) mergeMgr.getMergeResolverByName("Listing Merger");
		assertNotNull(listingMergeMgr);
		listingMergeMgr.setConflictDecision(decision);

		CountDownLatch startLatch = new CountDownLatch(1);
		CountDownLatch endLatch = new CountDownLatch(1);
		Thread t = new Thread((Runnable) () -> {
			try {
				startLatch.countDown();
				mergeMgr.merge(TaskMonitor.DUMMY);
				endLatch.countDown();
			}
			catch (CancelledException e1) {
				// can't happen; dummy monitor
			}
		}, "MergeManager Thread");
		t.start();

		waitForMergeToStart(5000, startLatch, endLatch);

		if (waitForVisibleWindow) {
			long total = 0;
			while (!mergeMgr.isMergeToolVisible()) {
				total += sleep();
				if (total >= 10000) {
					Assert.fail("Merge tool is not visible after (ms): " + total);
				}
			}
		}

	}

	private void waitForMergeToStart(int timeoutMS, CountDownLatch startLatch,
			CountDownLatch endLatch) throws Exception {

		try {
			assertTrue("Merge did not start in " + timeoutMS + "ms",
				startLatch.await(timeoutMS, TimeUnit.MILLISECONDS));
		}
		catch (InterruptedException e) {
			fail("Interrupted waiting for merge to start");
		}

		// now wait for the merge tool to appear or for the entire merge process to have 
		// ended
		waitForCondition(() -> {
			mergeTool = mergeMgr.getMergeTool();
			boolean ended = endLatch.getCount() == 0;
			return mergeTool != null || ended;
		});
	}

	public void waitForOKDialog(String title, int timeoutMS) {
		int totalTime = 0;
		while (!mergeMgr.processingCompleted()) {
			Window win = getWindowWithTitleContaining(title);
			if (win != null) {
				pressButtonByText(win, "OK");
				return;
			}

			totalTime += sleep();

			if (totalTime >= timeoutMS) {
				Assert.fail("Couldn't find '" + title + "' dialog with OK button.");
			}
		}
	}

	public void waitForReadTextDialog(String title, String startOfExpectedText, int timeoutMS) {
		waitForReadTextDialog(title, startOfExpectedText, timeoutMS, true);
	}

	public void waitForReadTextDialog(String title, String startOfExpectedText, int timeoutMS,
			boolean pressOK) {
		JDialog dialog = waitForJDialog(title);
		if (dialog != null && (dialog instanceof DockingDialog)) {
			DockingDialog dockingDialog = (DockingDialog) dialog;
			DialogComponentProvider dialogComponent = dockingDialog.getDialogComponent();
			if (dialogComponent instanceof ReadTextDialog) {
				JTextArea textArea = findComponent(dialog, JTextArea.class);
				assertNotNull(textArea);
				String text = textArea.getText();
				if (!text.startsWith(startOfExpectedText)) {
					Assert.fail("ReadTextDialog doesn't start with string '" + startOfExpectedText +
						"'. Instead has '" +
						text.substring(0, ((text.length() <= 80) ? text.length() : 80)) + "'.");
				}
				if (pressOK) {
					pressButtonByText(dialog, "OK");
				}
				return;
			}
		}

		Assert.fail("Couldn't find '" + title + "' ReadTextDialog with OK button.");
	}

	public Component waitForConflictsPanel(Class<? extends Component> conflictPanelClass,
			int timeoutMS) {
		int totalTime = 0;
		Window window = mergeTool.getToolFrame();
		while (totalTime <= timeoutMS) {
			if (mergeMgr.processingCompleted()) {
				Assert.fail("Expected conflict merge panel, '" + conflictPanelClass.getName() +
					"',  but merge has already completed.");
				return null;
			}
			if (window != null && window.isVisible()) {
				Component comp = findComponent(window, conflictPanelClass);
				if (comp != null) {
					return comp;
				}
			}
			totalTime += sleep();
		}
		Assert.fail("Couldn't find conflict merge panel, '" + conflictPanelClass.getName() + "'.");
		return null;
	}

//	@Override
//	protected void waitForApply(boolean enabled) throws Exception {
//		ListingMergePanel mergePanel = getMergePanel();
//		waitForApply(mergePanel, enabled);
//	}
//
//	protected void waitForApply(Container mergePanel, boolean enabled) throws Exception {
//		if (mergePanel == null && !enabled) {
//			return;// return immediately if no panel and waiting for button not enabled.
//		}
//
//		Window window = SwingUtilities.getWindowAncestor(mergePanel);
//		if ((window == null) && !enabled) {
//			return;// return immediately if no panel window and waiting for button not enabled.
//		}
//
//		if (!enabled && (window != null) && (window.isVisible())) {
//			return;// return immediately if merge panel is not visible when expecting apply disabled.
//		}
//
//		JButton applyButton = findButtonByText(window, "Apply");
//		assertNotNull(applyButton);
//
//		waitForCondition(() -> applyButton.isEnabled() == enabled,
//			"Failed waiting for Apply to be " + (enabled ? "enabled." : "disabled"));
//	}

	protected ListingMergePanel getMergePanel() throws Exception {
		return getMergePanel(ListingMergePanel.class);
	}

	// ************************************************************
	// ** Methods for interacting with the GUI.
	// ************************************************************

	protected void chooseVerticalCheckBoxes(final String[] componentNames) throws Exception {
		chooseVerticalCheckBoxes(componentNames, true);
	}

	protected void chooseVerticalCheckBoxes(final String[] componentNames, boolean apply)
			throws Exception {
		waitForPrompting();
		for (String componentName : componentNames) {
			chooseCheckBox(componentName, VerticalChoicesPanel.class);
		}
		if (apply) {
			waitForApply(true);
			Window window = SwingUtilities.getWindowAncestor(getMergePanel());
			assertNotNull(window);
			pressButtonByText(window, "Apply");
			waitForSwing();
			waitForApply(false);
		}
	}

	@Override
	protected void chooseApply() throws Exception {
		waitForApply(true);
		Window window = SwingUtilities.getWindowAncestor(getMergePanel());
		assertNotNull(window);
		pressButtonByText(window, "Apply");
		waitForSwing();
		waitForApply(false);
	}

	private void chooseCheckBox(final String componentName,
			final Class<? extends Component> conflictPanelClass) throws Exception {
		Window window = SwingUtilities.getWindowAncestor(getMergePanel());
		assertNotNull(window);
		Component comp = findComponent(window, conflictPanelClass);
		assertNotNull(comp);
		pressButtonByName((Container) comp, componentName, false);
		waitForSwing();
	}

	protected void chooseRadioButton(final String conflictName, final String componentName)
			throws Exception {
		checkConflictPanelTitle(conflictName, VerticalChoicesPanel.class);
		chooseRadioButton(componentName, VerticalChoicesPanel.class);
	}

	protected void chooseRadioButton(final String verticalChoiceRadioButtonName) throws Exception {
		chooseRadioButton(verticalChoiceRadioButtonName, VerticalChoicesPanel.class);
	}

	protected void chooseListRadioButton(final String listRadioButtonName) throws Exception {
		chooseRadioButton(listRadioButtonName, ScrollingListChoicesPanel.class);
	}

	protected void chooseButtonAndApply(final String conflictName, final String componentName)
			throws Exception {
		chooseButtonAndApply(conflictName, componentName, false);
	}

	protected void chooseButtonAndApply(final String conflictName, final String componentName,
			final boolean useForAll) throws Exception {
		checkConflictPanelTitle(conflictName, VerticalChoicesPanel.class);

		waitForPrompting();
		VerticalChoicesPanel verticalChoicesPanel =
			(VerticalChoicesPanel) getConflictsPanel(VerticalChoicesPanel.class);
		assertNotNull(verticalChoicesPanel);
		Window window = SwingUtilities.getWindowAncestor(verticalChoicesPanel);
		assertNotNull(window);

		pressButtonByName(verticalChoicesPanel, componentName, false);
		waitForSwing();
		runSwing(() -> verticalChoicesPanel.setUseForAll(useForAll));

		waitForApply(window, true, 2000);
		pressButtonByText(window, "Apply");
	}

	private void waitForApply(Window window, boolean enabled, int timeoutMS) throws Exception {

		JButton applyButton = findButtonByText(window, "Apply");
		assertNotNull(applyButton);
		waitForCondition(() -> applyButton.isEnabled() == enabled,
			"Failed waiting for Apply to be " + (enabled ? "enabled." : "disabled"));
	}

	private JPanel getConflictsPanel(final Class<? extends ConflictPanel> conflictPanelClass)
			throws Exception {

		long total = 0;
		ConflictPanel panel = findComponent(mergeTool.getToolFrame(), conflictPanelClass, true);
		while (panel == null) {

			panel = findComponent(mergeTool.getToolFrame(), conflictPanelClass, true);
			total += sleep();
			if (total >= 5000) {
				fail("Timed-out waiting for the conflict panel: " + conflictPanelClass);
			}
		}

		return panel;
	}

	/**
	 * Makes a user choice on a primary symbol conflict as indicated by option. 
	 * This is equivalent to the user clicking a mouse on a radio button 
	 * indicating which version's primary symbol is desired.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>KEEP_ORIGINAL</li>
	 * </ul>
	 */
	protected void chooseRadioButton(final String componentName,
			final Class<? extends Container> conflictPanelClass) throws Exception {
		chooseRadioButton(componentName, conflictPanelClass, true);
	}

	protected void chooseRadioButton(final String componentName,
			final Class<? extends Container> conflictPanelClass, boolean apply) throws Exception {
		waitForPrompting();
		Container mergePanel = getMergePanel(conflictPanelClass);
		Window window = SwingUtilities.getWindowAncestor(mergePanel);
		Container comp = findComponent(window, conflictPanelClass);
		assertNotNull(comp);

		pressButtonByName(comp, componentName, false);

		if (apply) {
			waitForApply(true);
			pressButtonByText(window, "Apply");
			waitForSwing();
			waitForApply(false);
		}
	}

	protected void checkConflictPanelTitle(final String conflictTitle,
			final Class<? extends JComponent> conflictPanelClass) throws Exception {
		waitForPrompting();
		Component mergePanel = getMergePanel(conflictPanelClass);
		assertNotNull("Timed-out waiting for merge panel", mergePanel);
		Window window = SwingUtilities.getWindowAncestor(mergePanel);
		if (window == null) {
			Msg.debug(this, "Unable to find conflict panel window for '" + conflictTitle + "'");
			printOpenWindows();
		}
		assertNotNull("Timed-out waiting for merge panel", window);
		JComponent comp = findComponent(window, conflictPanelClass);
		assertNotNull(comp);
		Border border = comp.getBorder();
		String title = ((TitledBorder) border).getTitle();
		assertEquals(conflictTitle, title);
	}

	protected void chooseVariousOptions(final String addrStr, final int[] options)
			throws Exception {
		chooseVariousOptions(addrStr, options, false);
	}

	protected void chooseVariousOptions(final String addrStr, final int[] options,
			boolean useForAll) throws Exception {
		waitForPrompting();
		Window window = SwingUtilities.getWindowAncestor(getMergePanel());
		ConflictInfoPanel infoComp = findComponent(window, ConflictInfoPanel.class);
		assertNotNull(infoComp);
		Address addr = addr(addrStr);
		assertEquals(addr.toString(), infoComp.getAddress().toString());
		VariousChoicesPanel choiceComp = findComponent(window, VariousChoicesPanel.class);
		assertNotNull(choiceComp);
		for (int row = 0; row < options.length; row++) {
			if (options[row] == CANCELED) {
				try {
					pressButtonByText(window, "Cancel", false);
					return;
				}
				catch (AssertionError e) {
					Assert.fail(e.getMessage());
				}
			}
			else if (options[row] == INFO_ROW) {
				continue;
			}
			String compName = choiceComp.getComponentName(row, optionToColumn(options[row]));
			Component comp = findComponentByName(choiceComp, compName, false);
			if (comp instanceof AbstractButton) {
				((AbstractButton) comp).setSelected(true);
			}
			else if (comp instanceof JCheckBox) {
				((JCheckBox) comp).setSelected(true);
			}
		}

		waitForSwing();
		setUseForAll(useForAll, VariousChoicesPanel.class);

		waitForApply(true);
		pressButtonByText(window, "Apply");
		waitForApply(false);
	}

	protected void chooseVariousOptions(final int[] options) throws Exception {
		waitForPrompting();
		Window window = SwingUtilities.getWindowAncestor(getMergePanel());

		VariousChoicesPanel choiceComp = findComponent(window, VariousChoicesPanel.class);
		assertNotNull(choiceComp);
		for (int row = 0; row < options.length; row++) {
			if (options[row] == CANCELED) {
				try {
					pressButtonByText(window, "Cancel", false);
					return;
				}
				catch (AssertionError e) {
					Assert.fail(e.getMessage());
				}
			}
			else if (options[row] == INFO_ROW) {
				continue;
			}
			String compName = choiceComp.getComponentName(row, optionToColumn(options[row]));
			Component comp = findComponentByName(choiceComp, compName, false);
			if (comp instanceof AbstractButton) {
				((AbstractButton) comp).setSelected(true);
			}
			else if (comp instanceof JCheckBox) {
				((JCheckBox) comp).setSelected(true);
			}
		}

		waitForApply(true);
		pressButtonByText(window, "Apply");
		waitForApply(false);
	}

	protected void chooseVariousOptionsForConflictType(final String conflictTitle,
			final int[] options) throws Exception {
		checkConflictPanelTitle(conflictTitle, VariousChoicesPanel.class);
		chooseVariousOptions(options);
	}

	private int optionToColumn(int option) {
		switch (option) {
			case KEEP_LATEST:
				return 1;
			case KEEP_MY:
				return 2;
			case KEEP_ORIGINAL:
				return 3;
		}
		return -1;
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>KEEP_ORIGINAL</li>
	 * <li>CANCELED</li>
	 * </ul>
	 */
	protected void chooseCodeUnit(String minAddress, String maxAddress, final int option)
			throws Exception {
		chooseCodeUnit(minAddress, maxAddress, option, false);
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>KEEP_ORIGINAL</li>
	 * <li>CANCELED</li>
	 * </ul>
	 * @param useForAll true indicates the Use For All check box should also get selected.
	 * @throws Exception if panel not available as expected
	 */
	protected void chooseCodeUnit(String minAddress, String maxAddress, final int option,
			final boolean useForAll) throws Exception {
		waitForPrompting();
		ListingMergePanel comp = getMergePanel();
		ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
		assertNotNull(infoComp);

		assertEquals("Byte / Code Unit", infoComp.getConflictType());
		assertEquals(addr(minAddress), infoComp.getAddress());
		AddressRange addressRange = infoComp.getAddressRange();
		assertEquals(addr(minAddress), addressRange.getMinAddress());
		assertEquals(addr(maxAddress), addressRange.getMaxAddress());

		if (option == CANCELED) {
			pressButtonByText(mergeTool.getToolFrame(), "Cancel", false);
			return;
		}

		if (option == KEEP_LATEST) {
			pressButtonByName(comp, "ChoiceComponentRow0Col1");
		}
		else if (option == KEEP_MY) {
			pressButtonByName(comp, "ChoiceComponentRow0Col2");
		}
		else if (option == KEEP_ORIGINAL) {
			pressButtonByName(comp, "ChoiceComponentRow0Col3");
		}

		waitForSwing();
		setUseForAll(useForAll, VariousChoicesPanel.class);
		waitForApply(true);

		Window windowAncestor = SwingUtilities.getWindowAncestor(getMergePanel());
		pressButtonByText(windowAncestor, "Apply");
		waitForApply(false);
	}

	protected void setUseForAll(boolean useForAll,
			Class<? extends ConflictPanel> conflictPanelClass) throws Exception {
		Window windowAncestor = SwingUtilities.getWindowAncestor(getMergePanel());
		assertNotNull(windowAncestor);
		ConflictPanel conflictPanel = findComponent(windowAncestor, conflictPanelClass, true);
		assertNotNull(conflictPanel);
		conflictPanel.setUseForAll(useForAll);
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>KEEP_ORIGINAL</li>
	 * <li>CANCELED</li>
	 * </ul>
	 */
	protected void chooseComment(final String commentType, final Address addr, final int option)
			throws Exception {
		chooseComment(commentType, addr, option, false);
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>KEEP_ORIGINAL</li>
	 * <li>CANCELED</li>
	 * </ul>
	 * @param useForAll true indicates that this should select the checkbox for 
	 * "Use For All" of this type of comment.
	 * @throws Exception if panel not available as expected
	 */
	protected void chooseComment(final String commentType, final Address addr, final int option,
			final boolean useForAll) throws Exception {
		waitForPrompting();
		ListingMergePanel comp = getMergePanel();
		assertNotNull(comp);
		Window window = SwingUtilities.getWindowAncestor(comp);
		ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
		assertNotNull(infoComp);

		assertEquals("Comment", infoComp.getConflictType());
		assertEquals(addr.toString(), infoComp.getAddress().toString());
		if (option == CANCELED) {
			pressButtonByText(mergeTool.getToolFrame(), "Cancel", false);
			return;
		}

		AbstractButton button;
		if ((option & KEEP_LATEST) != 0) {
			button = (AbstractButton) findComponentByName(comp, LATEST_BUTTON);
			if (button == null) {
				final JCheckBox checkbox = (JCheckBox) findComponentByName(comp, LATEST_CHECK_BOX);
				assertNotNull(checkbox);
				runSwing(() -> checkbox.doClick(), false);
			}
			else {
				pressButton(button, false);
			}
		}
		if ((option & KEEP_MY) != 0) {
			button = (AbstractButton) findComponentByName(comp, MY_BUTTON);
			if (button == null) {
				final JCheckBox checkbox = (JCheckBox) findComponentByName(comp, MY_CHECK_BOX);
				assertNotNull(checkbox);
				runSwing(() -> checkbox.doClick(), false);
			}
			else {
				pressButton(button, false);
			}
		}

		waitForSwing();
		setUseForAll(useForAll, VerticalChoicesPanel.class);
		waitForApply(true);

		pressButtonByText(window, "Apply");
		waitForApply(false);
	}

	protected void checkListingConflictInfo(final String conflictType, final Address addr)
			throws Exception {
		waitForPrompting();
		ListingMergePanel comp = getMergePanel();
		assertNotNull(comp);
		ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
		assertNotNull(infoComp);
		assertEquals(conflictType, infoComp.getConflictType());
		assertEquals(addr.toString(), infoComp.getAddress().toString());
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void chooseEquate(final String addr, final int opIndex, final int option)
			throws Exception {
		chooseEquate(addr, opIndex, option, false);
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void chooseEquate(final String addr, final int opIndex, final int option,
			final boolean useForAll) throws Exception {
		chooseOption("Equate", addr, option, useForAll);
	}

	protected void chooseReference(final String addr, final int opIndex, final int option,
			final boolean useForAll) throws Exception {
		chooseOption("Reference", addr, option, useForAll);
	}

	protected void chooseProgramContext(final String registerName, final int option,
			final boolean useForAll) throws Exception {
		Window window = SwingUtilities.getWindowAncestor(getMergePanel());
		final VerticalChoicesPanel verticalChoicesPanel =
			findComponent(window, VerticalChoicesPanel.class);
		TitledBorder titledBorder = (TitledBorder) getInstanceField("border", verticalChoicesPanel);
		String title = titledBorder.getTitle();
		assertEquals("Resolve \"" + registerName + "\" Register Value Conflict", title);

		if (option == CANCELED) {
			pressButtonByText(window, "Cancel", false);
			return;
		}

		String componentName = null;
		switch (option) {
			case KEEP_LATEST:
				componentName = LATEST_BUTTON;
				break;
			case KEEP_MY:
				componentName = MY_BUTTON;
				break;
			case KEEP_ORIGINAL:
				componentName = ORIGINAL_BUTTON;
				break;
			default:
				Assert.fail("Cannot choose the unrecognized option of " + option + ".");
		}
		AbstractButton button =
			(AbstractButton) findComponentByName(verticalChoicesPanel, componentName);
		assertNotNull(button);
		pressButton(button, false);

		setUseForAll(useForAll, VerticalChoicesPanel.class);
		waitForApply(true);

		Window windowAncestor = SwingUtilities.getWindowAncestor(getMergePanel());
		pressButtonByText(windowAncestor, "Apply");
		waitForApply(false);
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void verticalChooseFunction(final String addr, final int option) throws Exception {
		verticalChooseFunction(addr, option, false);
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void verticalChooseFunction(final String addr, final int option,
			final boolean useForAll) throws Exception {
		chooseOption("Function", addr, option, useForAll);
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void horizontalChooseFunction(final String addr, final int option) throws Exception {
		chooseVariousOptions(addr, new int[] { option }, false);
	}

	protected void horizontalChooseFunction(final String addr, final int option, boolean useForAll)
			throws Exception {
		chooseVariousOptions(addr, new int[] { option }, useForAll);
	}

	/**
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param addr indicates the address in conflict.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void chooseBookmark(final String addr, final int option, final boolean useForAll)
			throws Exception {
		chooseOption("Bookmark", addr, option, useForAll);
	}

	/**
	 * Checks for the indicated bookmark in the Result program.
	 * @param address indicates the address of the bookmark.
	 * @param type the bookmark type.
	 * @param category the bookmark category.
	 * @param comment the expected comment.
	 */
	protected void checkBookmark(final String address, final String type, final String category,
			final String comment) {
		Bookmark bookmark =
			resultProgram.getBookmarkManager().getBookmark(addr(address), type, category);
		assertNotNull("Couldn't get bookmark @ " + address + " of type '" + type +
			"' and category '" + category + "'", bookmark);
		assertEquals(comment, bookmark.getComment());
	}

	/**
	 * Checks that the indicated bookmark is not in the Result program.
	 * @param addr indicates the address of the bookmark.
	 * @param type the bookmark type.
	 * @param category the bookmark category.
	 */
	protected void noBookmark(final String address, final String type, final String category) {
		Bookmark bookmark =
			resultProgram.getBookmarkManager().getBookmark(addr(address), type, category);
		assertNull("Shouldn't get bookmark @ " + address + " of type '" + type +
			"' and category '" + category + "'", bookmark);
	}

	/**
	 * Verifies the address matches the one i the conflict information panel.
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param addr the expected address of the conflict
	 * @param property the name of the property (Not currently used)
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 * @param useForAll true indicates thatthis should select the checkbox for 
	 * "Use for all conflicts of this property type".
	 * @throws Exception if panel not available as expected
	 */
	protected void chooseUserDefined(final Address addr, final String property, final int option,
			final boolean useForAll) throws Exception {
		if (useForAll) {
			waitForPrompting();
			ListingMergePanel comp = getMergePanel();
			assertNotNull(comp);
			ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
			assertNotNull(infoComp);
			assertEquals("User Defined Property", infoComp.getConflictType());
			assertEquals(addr.toString(), infoComp.getAddress().toString());
			chooseCheckBox(ConflictPanel.USE_FOR_ALL_CHECKBOX, VerticalChoicesPanel.class);
		}
		chooseUserDefined(addr, property, option);
	}

	/**
	 * Verifies the address matches the one i the conflict information panel.
	 * Makes a user choice as indicated by option. This is equivalent to the user 
	 * clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param addr the expected address of the conflict
	 * @param property the name of the property (Not currently used)
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 * @throws Exception if panel not available as expected
	 */
	protected void chooseUserDefined(final Address addr, final String property, final int option)
			throws Exception {
		waitForPrompting();
		ListingMergePanel comp = getMergePanel();
		assertNotNull(comp);
		Window window = SwingUtilities.getWindowAncestor(comp);
		ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
		assertNotNull(infoComp);
		assertEquals("User Defined Property", infoComp.getConflictType());
		assertEquals(addr.toString(), infoComp.getAddress().toString());
		if (option == CANCELED) {
			pressButtonByText(window, "Cancel", false);
			return;
		}

		AbstractButton button;
		if ((option & KEEP_LATEST) != 0) {
			button = (AbstractButton) findComponentByName(comp, LATEST_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
		}
		if ((option & KEEP_MY) != 0) {
			button = (AbstractButton) findComponentByName(comp, MY_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
		}
		if ((option & KEEP_ORIGINAL) != 0) {
			button = (AbstractButton) findComponentByName(comp, ORIGINAL_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
		}

		waitForApply(true);
		pressButtonByText(window, "Apply");
		waitForApply(false);
	}

	/**
	 * Makes a user choice on a primary symbol conflict as indicated by option. 
	 * This is equivalent to the user clicking a mouse on a radio button 
	 * indicating which version's primary symbol is desired.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void choosePrimarySymbol(final String addrStr, final String latestName,
			final boolean latestIsGlobal, final String myName, final boolean myIsGlobal,
			final int option, final int timeoutMS) throws Exception {
		waitForPrompting();
		Address addr = addr(addrStr);
		ListingMergePanel comp = getMergePanel();
		assertNotNull(comp);
		Window window = SwingUtilities.getWindowAncestor(comp);
		ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
		assertNotNull(infoComp);
		assertEquals("Symbol", infoComp.getConflictType());
		assertEquals(addr.toString(), infoComp.getAddress().toString());
		if (option == CANCELED) {
			try {
				pressButtonByText(window, "Cancel", false);
				return;
			}
			catch (AssertionError e) {
				Assert.fail(e.getMessage());
			}
		}

		AbstractButton button;
		if ((option & KEEP_LATEST) != 0) {
			button = (AbstractButton) findComponentByName(comp, LATEST_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
			waitForSwing();
		}
		if ((option & KEEP_MY) != 0) {
			button = (AbstractButton) findComponentByName(comp, MY_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
			waitForSwing();
		}

		waitForApply(true);
		pressButtonByText(window, "Apply");
		waitForApply(false);
	}

	/**
	 * Makes a user choice on a primary symbol conflict as indicated by option. 
	 * This is equivalent to the user clicking a mouse on a radio button 
	 * indicating which version's primary symbol is desired.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void chooseLocalOrGlobalSymbol(final String addrStr, final String name,
			final boolean latestIsGlobal, final boolean myIsGlobal, final int option,
			final int timeoutMS) throws Exception {
		waitForPrompting();
		Address addr = addr(addrStr);
		ListingMergePanel comp = getMergePanel();
		assertNotNull(comp);
		Window window = SwingUtilities.getWindowAncestor(comp);
		ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
		assertNotNull(infoComp);
		assertEquals("Symbol", infoComp.getConflictType());
		assertEquals(addr.toString(), infoComp.getAddress().toString());
		if (option == CANCELED) {
			try {
				pressButtonByText(window, "Cancel", false);
				return;
			}
			catch (AssertionError e) {
				Assert.fail(e.getMessage());
			}
		}

		AbstractButton button;
		if ((option & KEEP_LATEST) != 0) {
			button = (AbstractButton) findComponentByName(comp, LATEST_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
			waitForSwing();
		}
		if ((option & KEEP_MY) != 0) {
			button = (AbstractButton) findComponentByName(comp, MY_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
			waitForSwing();
		}

		waitForApply(true);
		pressButtonByText(window, "Apply");
		waitForApply(false);
	}

	/**
	 * Makes a user choice on the named global symbol conflict as indicated by option. 
	 * This is equivalent to the user clicking a mouse on a radio button 
	 * indicating which version's primary symbol is desired.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void chooseGlobalSymbol(final String name, final String latestAddress,
			final String myAddress, final int option) throws Exception {
		waitForPrompting();
		Address latestAddr = addr(latestAddress);
		Address myAddr = addr(myAddress);
		Address minAddr = ((latestAddr.compareTo(myAddr) < 0) ? latestAddr : myAddr);
		ListingMergePanel comp = getMergePanel();
		assertNotNull(comp);
		Window window = SwingUtilities.getWindowAncestor(comp);
		ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
		assertNotNull(infoComp);
		assertEquals("Symbol", infoComp.getConflictType());
		assertEquals(minAddr.toString(), infoComp.getAddress().toString());
		if (option == CANCELED) {
			pressButtonByText(window, "Cancel", false);
			return;
		}

		AbstractButton button;
		if ((option & KEEP_LATEST) != 0) {
			button = (AbstractButton) findComponentByName(comp, LATEST_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
			waitForSwing();
		}
		if ((option & KEEP_MY) != 0) {
			button = (AbstractButton) findComponentByName(comp, MY_BUTTON);
			assertNotNull(button);
			pressButton(button, false);
			waitForSwing();
		}

		waitForApply(true);
		pressButtonByText(window, "Apply");
		waitForApply(false);
	}

	protected Function checkFunction(Program program, String entryPoint, String nameExpected,
			AddressSetView body) {
		Address addr = addr(program, entryPoint);
		Function function = program.getFunctionManager().getFunctionAt(addr);
		assertNotNull("Can't get function @ " + entryPoint, function);
		assertEquals(nameExpected, function.getName());
		assertEquals(body, function.getBody());
		return function;
	}

	protected void noFunction(Program program, String entryPoint) {
		Address addr = addr(program, entryPoint);
		Function function = program.getFunctionManager().getFunctionAt(addr);
		if (function != null) {
			Assert.fail("Unexpectedly found function '" + function.getName() + "' @ " + entryPoint);
		}
	}

	protected Function getFunction(Program program, String address) {
		Address addr = addr(program, address);
		return program.getFunctionManager().getFunctionAt(addr);
	}

	/**
	 * Makes a user choice on the named type of conflict as indicated by option. 
	 * This is equivalent to the user clicking a mouse on a radio button 
	 * indicating which version's option is desired.
	 * It can also be used to press the Cancel button on the merge.
	 * @param option indicates the button to choose.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * <li>KEEP_BOTH</li>
	 * </ul>
	 */
	protected void chooseOption(final String conflictType, final String address, final int option,
			boolean useForAll) throws Exception {
		waitForPrompting();
		Address addr = addr(address);
		ListingMergePanel comp = getMergePanel();
		assertNotNull(comp);
		Window window = SwingUtilities.getWindowAncestor(comp);
		ConflictInfoPanel infoComp = findComponent(comp, ConflictInfoPanel.class);
		assertNotNull(infoComp);
		assertEquals(conflictType, infoComp.getConflictType());
		assertEquals(addr.toString(), infoComp.getAddress().toString());
		if (option == CANCELED) {
			pressButtonByText(window, "Cancel", false);
			return;
		}

		AbstractButton button;
		String componentName = null;
		switch (option) {
			case KEEP_LATEST:
				componentName = LATEST_BUTTON;
				break;
			case KEEP_MY:
				componentName = MY_BUTTON;
				break;
			case KEEP_ORIGINAL:
				componentName = ORIGINAL_BUTTON;
				break;
			case REMOVE_LATEST:
				componentName = REMOVE_LATEST_BUTTON;
				break;
			case REMOVE_MY:
				componentName = REMOVE_MY_BUTTON;
				break;
			case RENAME_LATEST:
				componentName = RENAME_LATEST_BUTTON;
				break;
			case RENAME_MY:
				componentName = RENAME_MY_BUTTON;
				break;
			default:
				Assert.fail("Cannot choose the unrecognized option of " + option + ".");
		}
		button = (AbstractButton) findComponentByName(comp, componentName);
		assertNotNull(button);
		pressButton(button, false);
		waitForSwing();

		if (useForAll) {
			setUseForAll(useForAll, VerticalChoicesPanel.class);
		}

		waitForApply(true);
		Window windowAncestor = SwingUtilities.getWindowAncestor(getMergePanel());
		pressButtonByText(windowAncestor, "Apply");
		waitForApply(false);
	}

	protected Variable getStackVariable(Function f, int offset) {
		Variable[] vars = f.getVariables(VariableFilter.STACK_VARIABLE_FILTER);
		for (Variable variable : vars) {
			if (variable.getStackOffset() == offset) {
				return variable;
			}
		}
		return null;
	}

	protected Symbol createScopedSymbol(ProgramDB program, String address, String name)
			throws InvalidInputException {
		Address addr = addr(program, address);
		Namespace scope = program.getNamespaceManager().getNamespaceContaining(addr);
		assertTrue("Can't create Scoped symbol @ " + address,
			(!(scope instanceof GlobalNamespace)));
		return program.getSymbolTable().createLabel(addr, name, scope, SourceType.USER_DEFINED);
	}

	protected Symbol createGlobalSymbol(ProgramDB program, String address, String name)
			throws InvalidInputException {
		Address addr = addr(program, address);
		return program.getSymbolTable().createLabel(addr, name, null, SourceType.USER_DEFINED);
	}

	protected Symbol getScopedSymbol(ProgramDB program, String address, String name) {
		Address addr = addr(program, address);
		Namespace scope = program.getNamespaceManager().getNamespaceContaining(addr);
		return program.getSymbolTable().getSymbol(name, addr, scope);
	}

	protected Symbol getGlobalSymbol(ProgramDB program, String address, String name) {
		Address addr = addr(program, address);
		return program.getSymbolTable().getSymbol(name, addr, null);
	}

	protected void checkSymbol(Symbol symbol, String nameExpected, boolean isGlobalExpected) {
		assertNotNull(symbol);
		assertEquals(nameExpected, symbol.getName());
		assertEquals(isGlobalExpected, symbol.isGlobal());
	}

	/**
	 * Makes a user choice for a symbol conflict as indicated by option. This is equivalent to 
	 * the user clicking a mouse on a radio button indicating which program version to choose.
	 * It can also be used to press the Cancel button on the merge.
	 * @param addr indicates the address in conflict.
	 * @param option indicates the button to choose.
	 * @param useForAll true indicates the "Use For All" box should get checked for this choice
	 * before applying.
	 * <br>One of:
	 * <ul>
	 * <li>KEEP_LATEST</li>
	 * <li>KEEP_MY</li>
	 * <li>CANCEL</li>
	 * </ul>
	 */
	protected void chooseSymbol(final String addr, final int option, final boolean useForAll)
			throws Exception {
		chooseOption("Symbol", addr, option, useForAll);
	}

	/**
	 * This gets an array containing the bytes indicated by the string.
	 * It takes a string of the form "a5 32 b9", where each byte is two hex digits separated 
	 * by a space.
	 * @param hexBytesAsString is a string indicating the hexadecimal representation of the 
	 * bytes to put in the array.
	 * @return the array of bytes
	 * @throws a NumberFormatException if the string can't be parsed into an array of bytes.
	 */
	protected byte[] getHexByteArray(String hexBytesAsString) throws NumberFormatException {
		String[] hexByteStrings = hexBytesAsString.split(" ");
		byte[] bytes = new byte[hexByteStrings.length];
		for (int i = 0; i < hexByteStrings.length; i++) {
			int byteAsUnsignedInt = Integer.parseUnsignedInt(hexByteStrings[i], 16);
			bytes[i] = (byte) byteAsUnsignedInt;
		}
		return bytes;
	}

	protected void disassemble(Program pgm, AddressSetView addrSet) {
		Disassembler disassembler = Disassembler.getDisassembler(pgm, TaskMonitor.DUMMY,
			DisassemblerMessageListener.IGNORE);
		disassembler.disassemble(addrSet.getMinAddress(), addrSet, false);
	}

	protected void setupOverlapUseForAll() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					AddressSet body1001984 =
						new AddressSet(addr(program, "0x1001984"), addr(program, "0x100198a"));
					createFunction(program, "0x1001984", "FUN_01001984", body1001984);

					AddressSet body10029bc =
						new AddressSet(addr(program, "0x10029bc"), addr(program, "0x10029d3"));
					createFunction(program, "0x10029bc", "FUN_010029bc", body10029bc);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

	protected void setupRemoveConflictUseForAll() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x10031ee");
					removeFunction(program, "0x1003bed");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x10031ee");
					func.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					func = getFunction(program, "0x1003bed");
					func.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}
}
