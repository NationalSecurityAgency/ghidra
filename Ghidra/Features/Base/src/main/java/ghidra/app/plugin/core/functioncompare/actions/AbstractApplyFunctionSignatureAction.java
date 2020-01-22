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
package ghidra.app.plugin.core.functioncompare.actions;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.fieldpanel.internal.FieldPanelCoordinator;
import ghidra.app.util.viewer.util.CodeComparisonPanel;
import ghidra.app.util.viewer.util.CodeComparisonPanelActionContext;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionUtility;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Applies the signature of the function in the currently active side of a 
 * code comparison panel to the function in the other side of the panel
 * <p>
 * Each CodeComparisonPanel can extend this class in order to provide this action
 * using its context
 */
public abstract class AbstractApplyFunctionSignatureAction extends DockingAction {

	private static final String MENU_GROUP = "A0_Apply";
	private static final String HELP_TOPIC = "FunctionComparison";
	private static final String ACTION_NAME = "Apply Function Signature To Other Side";

	/**
	 * Constructor
	 * 
	 * @param owner the owner of this action
	 */
	public AbstractApplyFunctionSignatureAction(String owner) {
		super(ACTION_NAME, owner);

		setDescription(HTMLUtilities.toHTML("Apply the signature of the function in the " +
			"currently active side of a code comparison panel to the function in the other " +
			"side of the panel."));
		MenuData menuData = new MenuData(new String[] { ACTION_NAME }, null, MENU_GROUP);
		setPopupMenuData(menuData);
		setEnabled(true);
		setHelpLocation(new HelpLocation(HELP_TOPIC, ACTION_NAME));
	}

	@Override
	public abstract boolean isAddToPopup(ActionContext context);

	@Override
	public abstract boolean isEnabledForContext(ActionContext context);

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof CodeComparisonPanelActionContext) {
			CodeComparisonPanelActionContext compareContext =
				(CodeComparisonPanelActionContext) context;
			CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel =
				compareContext.getCodeComparisonPanel();
			Function leftFunction = codeComparisonPanel.getLeftFunction();
			Function rightFunction = codeComparisonPanel.getRightFunction();
			if (leftFunction == null || rightFunction == null) {
				return; // Can only apply if both sides have functions.
			}
			ComponentProvider componentProvider = context.getComponentProvider();
			boolean leftHasFocus = codeComparisonPanel.leftPanelHasFocus();
			boolean commit;
			if (leftHasFocus) {
				commit = updateFunction(componentProvider, rightFunction, leftFunction);
			}
			else {
				commit = updateFunction(componentProvider, leftFunction, rightFunction);
			}
			if (commit) {
				// Refresh the side that had its function signature changed (the side without focus).
				if (leftHasFocus) {
					codeComparisonPanel.refreshRightPanel();
				}
				else {
					codeComparisonPanel.refreshLeftPanel();
				}
			}
		}
	}

	/**
	 * Returns true if the comparison panel opposite the one with focus,
	 * is read-only
	 * <p>
	 * eg: if the right-side panel has focus, and the left-side panel is 
	 * read-only, this will return true
	 *  
	 * @param codeComparisonPanel the comparison panel
	 * @return true if the non-focused panel is read-only
	 */
	protected boolean hasReadOnlyNonFocusedSide(
			CodeComparisonPanel<? extends FieldPanelCoordinator> codeComparisonPanel) {
		Function leftFunction = codeComparisonPanel.getLeftFunction();
		Function rightFunction = codeComparisonPanel.getRightFunction();

		if (leftFunction == null || rightFunction == null) {
			return false; // Doesn't have a function on both sides.
		}

		boolean leftHasFocus = codeComparisonPanel.leftPanelHasFocus();
		Program leftProgram = leftFunction.getProgram();
		Program rightProgram = rightFunction.getProgram();
		return (!leftHasFocus && leftProgram.getDomainFile().isReadOnly()) ||
			(leftHasFocus && rightProgram.getDomainFile().isReadOnly());
	}

	/**
	 * Attempts to change the signature of a function to that of another
	 * function
	 * 
	 * @param provider the parent component provider 
	 * @param destinationFunction the function to change
	 * @param sourceFunction the function to copy
	 * @return true if the operation was successful
	 */
	protected boolean updateFunction(ComponentProvider provider, Function destinationFunction,
			Function sourceFunction) {

		Program program = destinationFunction.getProgram();
		int txID = program.startTransaction(ACTION_NAME);
		boolean commit = false;

		try {
			FunctionUtility.updateFunction(destinationFunction, sourceFunction);
			commit = true;
		}
		catch (InvalidInputException | DuplicateNameException e) {
			String message = "Couldn't apply the function signature from " +
				sourceFunction.getName() + " to " + destinationFunction.getName() + " @ " +
				destinationFunction.getEntryPoint().toString() + ". " + e.getMessage();
			Msg.showError(this, provider.getComponent(), ACTION_NAME, message, e);
		}
		finally {
			program.endTransaction(txID, commit);
		}

		return commit;
	}
}
