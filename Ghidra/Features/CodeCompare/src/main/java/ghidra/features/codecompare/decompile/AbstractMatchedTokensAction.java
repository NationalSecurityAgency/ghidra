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
package ghidra.features.codecompare.decompile;

import docking.ActionContext;
import docking.action.DockingAction;

/**
 * This is a base class for actions in a {@link DecompilerCodeComparisonPanel}
 */
public abstract class AbstractMatchedTokensAction extends DockingAction {
	protected static final String MENU_PARENT = "Apply From Other Function";
	protected static final String HELP_TOPIC = "FunctionComparison";

	protected DecompilerCodeComparisonPanel diffPanel;
	protected boolean disableOnReadOnly;

	/**
	 * Constructor
	 * 
	 * @param actionName name of action
	 * @param owner owner of action
	 * @param diffPanel diff panel containing action
	 * @param disableOnReadOnly if true, action will be disabled for read-only programs
	 */
	public AbstractMatchedTokensAction(String actionName, String owner,
			DecompilerCodeComparisonPanel diffPanel, boolean disableOnReadOnly) {
		super(actionName, owner);
		this.diffPanel = diffPanel;
		this.disableOnReadOnly = disableOnReadOnly;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof DualDecompilerActionContext compareContext)) {
			return;
		}

		dualDecompilerActionPerformed(compareContext);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DualDecompilerActionContext compareContext)) {
			return false;
		}

		if (disableOnReadOnly) {
			if (compareContext.isActiveProgramReadOnly()) {
				return false;  // program is read-only, don't enable action
			}
		}

		return isEnabledForDualDecompilerContext(compareContext);
	}

	/**
	 * Subclasses return true if they are enabled for the given context
	 * 
	 * @param context the context
	 * @return true if enabled
	 */
	protected abstract boolean isEnabledForDualDecompilerContext(
			DualDecompilerActionContext context);

	/**
	 * Subclasses will perform their work in this method
	 * @param context the context
	 */
	protected abstract void dualDecompilerActionPerformed(DualDecompilerActionContext context);

}
