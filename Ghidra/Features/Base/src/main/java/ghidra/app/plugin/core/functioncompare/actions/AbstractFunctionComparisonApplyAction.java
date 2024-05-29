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
import docking.action.DockingAction;
import ghidra.app.util.viewer.util.CodeComparisonActionContext;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Base classes for applying function information from a one side or the other in the function
 * comparison window
 */
public abstract class AbstractFunctionComparisonApplyAction extends DockingAction {
	protected static final String MENU_PARENT = "Apply From Other";
	protected static final String MENU_GROUP = "A0_Apply";
	protected static final String HELP_TOPIC = "FunctionComparison";

	/**
	 * Constructor for base apply action
	 * @param name the name of the action
	 * @param owner the owner of the action
	 * the dual listing view or the dual decompiler view each of which produce their own action
	 * context types. Each different view creates their own version of each action using the
	 * context handler appropriate for that view.
	 */
	public AbstractFunctionComparisonApplyAction(String name, String owner) {
		super(name, owner);

	}

	@Override
	public boolean isValidContext(ActionContext context) {
		return context instanceof CodeComparisonActionContext;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (context instanceof CodeComparisonActionContext comparisonContext) {
			return isEnabledForContext(comparisonContext);
		}
		return false;
	}

	private boolean isEnabledForContext(CodeComparisonActionContext context) {
		Function source = context.getSourceFunction();
		Function target = context.getTargetFunction();
		if (source == null || target == null) {
			return false;
		}
		return !target.getProgram().getDomainFile().isReadOnly();

	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof CodeComparisonActionContext comparisonContext) {
			doActionPerformed(comparisonContext);
		}
	}

	private void doActionPerformed(CodeComparisonActionContext context) {
		Function source = context.getSourceFunction();
		Function target = context.getTargetFunction();
		Program program = target.getProgram();

		try {
			program.withTransaction(getName(), () -> applyFunctionData(source, target));
		}
		catch (Exception e) {
			String message = "Failed to apply " + source.getName() + " to " + target.getName() +
				" @ " + target.getEntryPoint().toString() + ". " + e.getMessage();
			Msg.showError(this, null, getName(), message, e);
		}

	}

	/**
	 * Subclasses override this method to apply function information from the source to the target.
	 * @param source the source function to get information from
	 * @param target the target function to apply information to
	 * @throws Exception throws a variety of exceptions depending on what is being applied and
	 * the apply fails.
	 */
	protected abstract void applyFunctionData(Function source, Function target) throws Exception;
}
