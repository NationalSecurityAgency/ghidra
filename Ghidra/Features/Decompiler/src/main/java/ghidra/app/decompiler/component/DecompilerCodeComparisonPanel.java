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
package ghidra.app.decompiler.component;

import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.label.GDHtmlLabel;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.util.viewer.listingpanel.ProgramLocationListener;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.app.util.viewer.util.TitledPanel;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.util.FunctionUtility;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;

/**
 * Panel that displays two decompilers for comparison
 */
public abstract class DecompilerCodeComparisonPanel<T extends DualDecompilerFieldPanelCoordinator>
		extends CodeComparisonPanel<DualDecompilerFieldPanelCoordinator> {

	private static final String NO_FUNCTION_TITLE = "No Function";
	final static String OPTIONS_TITLE = "Decompiler";

	private JSplitPane splitPane;
	private CDisplayPanel[] cPanels = new CDisplayPanel[2];
	private DualDecompilerFieldPanelCoordinator dualDecompilerCoordinator;
	private DecompileData leftDecompileData;
	private DecompileData rightDecompileData;
	private boolean isMatchingConstantsExactly = true;
	private DecompileOptions leftDecompileOptions;
	private DecompileOptions rightDecompileOptions;
	private ApplyFunctionSignatureAction applyFunctionSignatureAction;

	private ClangHighlightController[] highlightControllers = new ClangHighlightController[2];
	private ArrayList<DualDecompileResultsListener> dualDecompileResultsListenerList =
		new ArrayList<>();
	private String leftTitle = NO_FUNCTION_TITLE;
	private String rightTitle = NO_FUNCTION_TITLE;
	private ProgramLocationListener leftDecompilerLocationListener;
	private ProgramLocationListener rightDecompilerLocationListener;

	/**
	 * Creates a comparison panel with two decompilers
	 * 
	 * @param owner the owner of this panel
	 * @param tool the tool displaying this panel
	 */
	public DecompilerCodeComparisonPanel(String owner, PluginTool tool) {
		super(owner, tool);
		functions = new Function[2];

		buildPanel();
		loadFunctions(null, null);

		highlightControllers[LEFT] = new LocationClangHighlightController();
		highlightControllers[RIGHT] = new LocationClangHighlightController();
		setHighlightControllers(highlightControllers[LEFT], highlightControllers[RIGHT]);

		initialize();
	}

	private void initialize() {
		ToolOptions options = tool.getOptions(OPTIONS_TITLE);
		leftDecompileOptions.grabFromToolAndProgram(null, options,
			(functions[LEFT] != null) ? functions[LEFT].getProgram() : null);
		rightDecompileOptions.grabFromToolAndProgram(null, options,
			(functions[RIGHT] != null) ? functions[RIGHT].getProgram() : null);
		setFieldPanelCoordinator(createFieldPanelCoordinator());
		setScrollingSyncState(true);
		createActions();
	}

	@Override
	public JComponent getComponent() {
		return this;
	}

	@Override
	public String getTitle() {
		return "Decompile View";
	}

	@Override
	public void setVisible(boolean aFlag) {
		super.setVisible(aFlag);
		// If actions are added in the future, you may need to update their enablement here.
		// The applyFunctionSignatureAction enablement is already handled via context.
	}

	private void setTitles(String leftTitle, String rightTitle) {
		setLeftTitle(leftTitle);
		setRightTitle(rightTitle);
	}

	private void setTitle(TitledPanel titlePanel, String titlePrefix, String title) {
		if (!titlePrefix.isEmpty()) {
			titlePrefix += " "; // Add a space between prefix and title.
		}
		String htmlPrefix = "<HTML>";
		if (title.startsWith(htmlPrefix)) {
			titlePanel.setTitleName(htmlPrefix + HTMLUtilities.friendlyEncodeHTML(titlePrefix) +
				title.substring(htmlPrefix.length()));
		}
		else {
			titlePanel.setTitleName(titlePrefix + title);
		}
	}

	/**
	 * Sets the title for the left side's decompiler.
	 * @param leftTitle the title
	 */
	public void setLeftTitle(String leftTitle) {
		this.leftTitle = leftTitle;
		setTitle(titlePanels[LEFT], leftTitlePrefix, leftTitle);
	}

	/**
	 * Sets the title for the right side's decompiler.
	 * @param rightTitle the title
	 */
	public void setRightTitle(String rightTitle) {
		this.rightTitle = rightTitle;
		setTitle(titlePanels[RIGHT], rightTitlePrefix, rightTitle);
	}

	private void setTitles(Function leftFunction, Function rightFunction) {
		setTitles(getTitleForFunction(leftFunction), getTitleForFunction(rightFunction));
	}

	private String getTitleForFunction(Function function) {
		String title = NO_FUNCTION_TITLE;
		if (function != null) {
			String programName = function.getProgram().getDomainFile().getPathname();
			title = function.getName(true) + "  [" + programName + "]";
		}
		return title;
	}

	public boolean isMatchingConstantsExactly() {
		return isMatchingConstantsExactly;
	}

	@Override
	public void loadFunctions(Function leftFunction, Function rightFunction) {
		if (leftFunction == functions[LEFT] && rightFunction == functions[RIGHT]) {
			return;
		}

		// Clear the scroll info and highlight info to prevent unnecessary highlighting, etc.
		if (leftFunction != functions[LEFT]) {
			leftDecompileData = null;
		}
		if (rightFunction != functions[RIGHT]) {
			rightDecompileData = null;
		}
		notifyDecompileResultsListeners();

		Program leftProgram = (leftFunction != null) ? leftFunction.getProgram() : null;
		Program rightProgram = (rightFunction != null) ? rightFunction.getProgram() : null;
		setPrograms(leftProgram, rightProgram);

		loadLeftFunction(leftFunction);
		loadRightFunction(rightFunction);

		if (getShowTitles()) {
			setTitles(leftFunction, rightFunction);
		}
		else {
			setTitles("", "");
		}
		if (dualDecompilerCoordinator != null) {
			dualDecompilerCoordinator.leftLocationChanged((ProgramLocation) null);
		}
	}

	private void notifyDecompileResultsListeners() {
		// Notify any decompile results listener we have new left or right decompile results.
		for (DualDecompileResultsListener listener : dualDecompileResultsListenerList) {
			listener.decompileResultsSet(leftDecompileData, rightDecompileData);
		}
	}

	private void loadLeftFunction(Function function) {
		if (function == functions[LEFT]) {
			return;
		}
		functions[LEFT] = function;
		cPanels[LEFT].showFunction(function);
	}

	private void loadRightFunction(Function function) {
		if (function == functions[RIGHT]) {
			return;
		}
		functions[RIGHT] = function;
		cPanels[RIGHT].showFunction(function);
	}

	private void buildPanel() {
		setLayout(new BorderLayout());
		leftDecompileOptions = new DecompileOptions();
		rightDecompileOptions = new DecompileOptions();
//		Options options = tool.getOptions(OPTIONS_TITLE);
//		leftDecompileOptions.grabFromToolAndProgram(null, options,
//			(functions[LEFT] != null) ? functions[LEFT].getProgram() : null);
//		rightDecompileOptions.grabFromToolAndProgram(null, options,
//			(functions[LEFT] != null) ? functions[RIGHT].getProgram() : null);

		cPanels[LEFT] = new CDisplayPanel(leftDecompileOptions,
			decompileData -> leftDecompileDataSet(decompileData));
		cPanels[RIGHT] = new CDisplayPanel(rightDecompileOptions,
			decompileData -> rightDecompileDataSet(decompileData));

		leftDecompilerLocationListener = (leftLocation, trigger) -> {
			if (dualDecompilerCoordinator != null) {
				dualDecompilerCoordinator.leftLocationChanged(leftLocation);
			}
		};
		rightDecompilerLocationListener = (rightLocation, trigger) -> {
			if (dualDecompilerCoordinator != null) {
				dualDecompilerCoordinator.rightLocationChanged(rightLocation);
			}
		};
		cPanels[LEFT].setProgramLocationListener(leftDecompilerLocationListener);
		cPanels[RIGHT].setProgramLocationListener(rightDecompilerLocationListener);

		// Initialize focus listeners on decompiler panels.
		for (int i = 0; i < cPanels.length; i++) {
			FieldPanel fieldPanel = cPanels[i].getDecompilerPanel().getFieldPanel();
			fieldPanel.addFocusListener(this);
			fieldPanel.addMouseListener(new DualDecompilerMouseListener(i));
		}
		setDualPanelFocus(currProgramIndex);

		String leftTitle1 = FunctionUtility.getFunctionTitle(functions[LEFT]);
		String rightTitle1 = FunctionUtility.getFunctionTitle(functions[RIGHT]);

		// use mutable labels, as the titles update when functions are selected
		GDHtmlLabel leftTitleLabel = new GDHtmlLabel(leftTitle1);
		GDHtmlLabel rightTitleLabel = new GDHtmlLabel(rightTitle1);

		titlePanels[LEFT] = new TitledPanel(leftTitleLabel, cPanels[LEFT], 5);
		titlePanels[RIGHT] = new TitledPanel(rightTitleLabel, cPanels[RIGHT], 5);

		// Set the MINIMUM_PANEL_WIDTH for the left and right panel to prevent the split pane's 
		// divider from becoming locked (can't be moved) due to extra long title names.
		titlePanels[LEFT].setMinimumSize(
			new Dimension(MINIMUM_PANEL_WIDTH, titlePanels[LEFT].getMinimumSize().height));
		titlePanels[RIGHT].setMinimumSize(
			new Dimension(MINIMUM_PANEL_WIDTH, titlePanels[RIGHT].getMinimumSize().height));

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, true, titlePanels[LEFT],
			titlePanels[RIGHT]);
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(4);
		splitPane.setBorder(BorderFactory.createEmptyBorder());
		add(splitPane, BorderLayout.CENTER);
	}

	/**
	 * Adds the indicated listener to be notified when the decompile results have completed.
	 * @param listener the listener
	 * @return true if the listener was added.
	 */
	public boolean addDualDecompileResultsListener(DualDecompileResultsListener listener) {
		return dualDecompileResultsListenerList.add(listener);
	}

	/**
	 * Removes the indicated listener from being notified about decompile results.
	 * @param listener the listener
	 * @return true if the listener was removed.
	 */
	public boolean removeDualDecompileResultsListener(DualDecompileResultsListener listener) {
		return dualDecompileResultsListenerList.remove(listener);
	}

	/**
	 * Sets the highlight controllers for both decompiler panels.
	 * @param leftHighlightController the left side's highlight controller
	 * @param rightHighlightController the right side's highlight controller
	 */
	public void setHighlightControllers(ClangHighlightController leftHighlightController,
			ClangHighlightController rightHighlightController) {

		highlightControllers[LEFT] = leftHighlightController;
		highlightControllers[RIGHT] = rightHighlightController;
		cPanels[LEFT].getDecompilerPanel().setHighlightController(leftHighlightController);
		cPanels[RIGHT].getDecompilerPanel().setHighlightController(rightHighlightController);
	}

	/**
	 * Sets the coordinator for the two decompiler panels within this code comparison panel. 
	 * It coordinates their scrolling and location synchronization.
	 * @param fieldPanelCoordinator the coordinator for the two decompiler panels
	 */
	@Override
	public void setFieldPanelCoordinator(
			DualDecompilerFieldPanelCoordinator fieldPanelCoordinator) {

		if (this.dualDecompilerCoordinator == fieldPanelCoordinator) {
			return;
		}
		if (this.dualDecompilerCoordinator != null) {
			this.dualDecompilerCoordinator.dispose();
			cPanels[LEFT].setProgramLocationListener(null);
			cPanels[RIGHT].setProgramLocationListener(null);
		}

		this.dualDecompilerCoordinator = fieldPanelCoordinator;

		if (fieldPanelCoordinator != null) {
			cPanels[LEFT].setProgramLocationListener(leftDecompilerLocationListener);
			cPanels[RIGHT].setProgramLocationListener(rightDecompilerLocationListener);
			CDisplayPanel focusedDecompilerPanel = getFocusedDecompilerPanel();
			ProgramLocation programLocation =
				focusedDecompilerPanel.getDecompilerPanel().getCurrentLocation();
			if (programLocation != null) {
				focusedDecompilerPanel.locationChanged(programLocation);
			}
		}
	}

	protected void rightDecompileDataSet(DecompileData decompileData) {
		rightDecompileData = decompileData;
		notifyDecompileResultsListeners();
	}

	protected void leftDecompileDataSet(DecompileData decompileData) {
		leftDecompileData = decompileData;
		notifyDecompileResultsListeners();
	}

	/**
	 * Sets the component displayed in the top of this panel.
	 * @param comp the component.
	 */
	public void setTopComponent(JComponent comp) {
		if (topComp == comp) {
			return;
		}
		if (topComp != null) {
			remove(topComp);
		}
		topComp = comp;
		if (topComp != null) {
			add(topComp, BorderLayout.NORTH);
		}
		validate();
	}

	/**
	 * Sets the component displayed in the bottom of this panel.
	 * @param comp the component.
	 */
	public void setBottomComponent(JComponent comp) {
		if (bottomComp == comp) {
			return;
		}
		if (bottomComp != null) {
			remove(bottomComp);
		}
		validate(); // Since we are removing this while the panel is on the screen.
		bottomComp = comp;
		if (bottomComp != null) {
			add(bottomComp, BorderLayout.SOUTH);
		}
		validate(); // Since we are adding this while the panel is on the screen.
	}

	/**
	 * Gets the display panel from the left or right side that has or last had focus.
	 * @return the last C display panel with focus
	 */
	public CDisplayPanel getFocusedDecompilerPanel() {
		return cPanels[currProgramIndex];
	}

	/**
	 * Gets the left side's C display panel.
	 * @return the left C display panel
	 */
	public CDisplayPanel getLeftPanel() {
		return cPanels[LEFT];
	}

	/**
	 * Gets the right side's C display panel.
	 * @return the right C display panel
	 */
	public CDisplayPanel getRightPanel() {
		return cPanels[RIGHT];
	}

	@Override
	public void dispose() {
		setFieldPanelCoordinator(null);
		cPanels[LEFT].dispose();
		cPanels[RIGHT].dispose();
	}

	@Override
	public void focusGained(FocusEvent e) {
		Component comp = e.getComponent();
		for (int i = 0; i < cPanels.length; i++) {
			if (cPanels[i].getDecompilerPanel().getFieldPanel() == comp) {
				setDualPanelFocus(i);
			}
		}

		// Kick the tool so action buttons will be updated
		tool.getActiveComponentProvider().contextChanged();
	}

	private void setDualPanelFocus(int leftOrRight) {
		currProgramIndex = leftOrRight;
		cPanels[leftOrRight].setBorder(FOCUS_BORDER);
		cPanels[((leftOrRight == LEFT) ? RIGHT : LEFT)].setBorder(NON_FOCUS_BORDER);
	}

	@SuppressWarnings("unused")
	private void clearBothDisplaysAndShowMessage(String message) {
		cPanels[LEFT].clearAndShowMessage(message);
		cPanels[RIGHT].clearAndShowMessage(message);
	}

	/**
	 * Disable mouse navigation from within this dual decompiler panel.
	 * @param enabled false disables navigation
	 */
	@Override
	public void setMouseNavigationEnabled(boolean enabled) {
		cPanels[LEFT].setMouseNavigationEnabled(enabled);
		cPanels[RIGHT].setMouseNavigationEnabled(enabled);
	}

	@Override
	protected void setPrograms(Program leftProgram, Program rightProgram) {
		ToolOptions options = (tool != null) ? tool.getOptions(OPTIONS_TITLE) : null;
		if (leftProgram != programs[LEFT]) {
			programs[LEFT] = leftProgram;
			if (options != null) {
				leftDecompileOptions.grabFromToolAndProgram(null, options, leftProgram);
			}
		}
		if (rightProgram != programs[RIGHT]) {
			programs[RIGHT] = rightProgram;
			if (options != null) {
				rightDecompileOptions.grabFromToolAndProgram(null, options, rightProgram);
			}
		}
	}

	@Override
	public void loadData(Data leftData, Data rightData) {
		loadFunctions(null, null);
	}

	@Override
	public void loadAddresses(Program leftProgram, Program rightProgram,
			AddressSetView leftAddresses, AddressSetView rightAddresses) {
		loadFunctions(null, null);
	}

	/**
	 * Gets the left side's decompiler panel.
	 * @return the left decompiler panel
	 */
	public DecompilerPanel getLeftDecompilerPanel() {
		return cPanels[LEFT].getDecompilerPanel();
	}

	/**
	 * Gets the right side's decompiler panel.
	 * @return the right decompiler panel
	 */
	public DecompilerPanel getRightDecompilerPanel() {
		return cPanels[RIGHT].getDecompilerPanel();
	}

	@Override
	public void updateActionEnablement() {
		// Nothing to do.

		// applyFunctionSignature enablement is handled by context.
	}

	/**
	 * Creates the actions provided by this panel.
	 */
	protected void createActions() {
		applyFunctionSignatureAction = new ApplyFunctionSignatureAction(owner);
	}

	@Override
	public DockingAction[] getActions() {
		DockingAction[] codeCompActions = super.getActions();
		DockingAction[] otherActions = new DockingAction[] { applyFunctionSignatureAction };
		int compCount = codeCompActions.length;
		int otherCount = otherActions.length;
		DockingAction[] actions = new DockingAction[compCount + otherCount];
		System.arraycopy(codeCompActions, 0, actions, 0, compCount);
		System.arraycopy(otherActions, 0, actions, compCount, otherCount);
		return actions;
	}

	@Override
	public abstract Class<? extends DecompilerCodeComparisonPanel<? extends FieldPanelCoordinator>> getPanelThisSupersedes();

	@Override
	public ActionContext getActionContext(ComponentProvider provider, MouseEvent event) {

		Component component = event == null ? null : event.getComponent();
		CDisplayPanel focusedDecompilerPanel = getFocusedDecompilerPanel();
		DualDecompilerActionContext dualDecompContext =
			new DualDecompilerActionContext(provider, focusedDecompilerPanel, component);
		dualDecompContext.setCodeComparisonPanel(this);
		return dualDecompContext;
	}

	@Override
	public void programRestored(Program program) {
		Function leftFunction = getLeftFunction();
		Function rightFunction = getRightFunction();
		Program leftProgram = (leftFunction != null) ? leftFunction.getProgram() : null;
		Program rightProgram = (rightFunction != null) ? rightFunction.getProgram() : null;
		if (leftProgram == program) {
			titlePanels[LEFT].setTitleName(FunctionUtility.getFunctionTitle(leftFunction));
			refreshLeftPanel();
		}
		if (rightProgram == program) {
			titlePanels[RIGHT].setTitleName(FunctionUtility.getFunctionTitle(rightFunction));
			refreshRightPanel();
		}
	}

	private void refreshPanel(int leftOrRight) {
		// Hold onto functions for reloading them after the indicated side is cleared,
		// because that will have cleared it in the functions array.
		Function leftFunction = functions[LEFT];
		Function rightFunction = functions[RIGHT];

		// Save the location so it can be restored after getting new decompiler results.
		FieldLocation leftCursorLocation =
			getLeftDecompilerPanel().getFieldPanel().getCursorLocation();
		FieldLocation rightCursorLocation =
			getRightDecompilerPanel().getFieldPanel().getCursorLocation();

		MyDecompileResultsListener listener =
			new MyDecompileResultsListener(leftCursorLocation, rightCursorLocation);

		// Clear any previous listener that is for a decompiler load that hasn't finished.
		// This can simply clear since it is the only one that is adding them to the list.
		dualDecompileResultsListenerList.clear();

		// Clear the left or right function by passing null to the load method
		// and then reload it below to get it to update.
		loadFunctions(((leftOrRight == LEFT) ? null : leftFunction),
			((leftOrRight == RIGHT) ? null : rightFunction));

		// Setup to restore location to left or right decompiler panel.
		addDualDecompileResultsListener(listener);

		// Reload the left or right function to get it to update.
		loadFunctions(leftFunction, rightFunction);
	}

	/**
	 * Refreshes the left side of this panel.
	 */
	@Override
	public void refreshLeftPanel() {
		refreshPanel(LEFT);
	}

	/**
	 * Refreshes the right side of this panel.
	 */
	@Override
	public void refreshRightPanel() {
		refreshPanel(RIGHT);
	}

	@Override
	public boolean leftPanelHasFocus() {
		return currProgramIndex == LEFT;
	}

	@Override
	public void setTitlePrefixes(String leftTitlePrefix, String rightTitlePrefix) {
		this.leftTitlePrefix = leftTitlePrefix;
		this.rightTitlePrefix = rightTitlePrefix;
		setTitles(leftTitle, rightTitle);
	}

	@Override
	public AddressSetView getLeftAddresses() {
		return (functions[LEFT] != null) ? functions[LEFT].getBody() : EMPTY_ADDRESS_SET;
	}

	@Override
	public AddressSetView getRightAddresses() {
		return (functions[RIGHT] != null) ? functions[RIGHT].getBody() : EMPTY_ADDRESS_SET;
	}

	private class MyDecompileResultsListener implements DualDecompileResultsListener {

		private FieldLocation leftCursorLocation;
		private FieldLocation rightCursorLocation;

		private MyDecompileResultsListener(FieldLocation leftCursorLocation,
				FieldLocation rightCursorLocation) {
			this.leftCursorLocation = leftCursorLocation;
			this.rightCursorLocation = rightCursorLocation;
		}

		@Override
		public void decompileResultsSet(final DecompileData myLeftDecompileData,
				final DecompileData myRightDecompileData) {
			SwingUtilities.invokeLater(() -> {
				if (myLeftDecompileData != null) {
					// The left side may have reloaded with decompiler results,
					// so restore the cursor location.
					restoreCursor(getLeftDecompilerPanel(), leftCursorLocation);
				}
				if (myRightDecompileData != null) {
					// The right side may have reloaded with decompiler results,
					// so restore the cursor location.
					restoreCursor(getRightDecompilerPanel(), rightCursorLocation);
				}

				// The listener did its job so now remove it.
				removeDualDecompileResultsListener(MyDecompileResultsListener.this);
			});
		}

		private void restoreCursor(DecompilerPanel decompilerPanel, FieldLocation cursorLocation) {
			FieldPanel fieldPanel = decompilerPanel.getFieldPanel();
			FieldLocation currentLocation = fieldPanel.getCursorLocation();
			if (cursorLocation != null && !cursorLocation.equals(currentLocation)) {
				fieldPanel.setCursorPosition(cursorLocation.getIndex(),
					cursorLocation.getFieldNum(), cursorLocation.getRow(), cursorLocation.getCol());
			}
		}
	}

	private class DualDecompilerMouseListener extends MouseAdapter {

		private int leftOrRight;

		DualDecompilerMouseListener(int leftOrRight) {
			this.leftOrRight = leftOrRight;
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			setDualPanelFocus(leftOrRight);
		}
	}

	@Override
	public FieldPanel getLeftFieldPanel() {
		return getLeftDecompilerPanel().getFieldPanel();
	}

	@Override
	public FieldPanel getRightFieldPanel() {
		return getRightDecompilerPanel().getFieldPanel();
	}

	@Override
	protected abstract DualDecompilerFieldPanelCoordinator createFieldPanelCoordinator();
}
