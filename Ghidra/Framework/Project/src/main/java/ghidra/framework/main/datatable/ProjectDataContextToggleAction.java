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
package ghidra.framework.main.datatable;

import docking.ActionContext;
import docking.action.ToggleDockingAction;

public abstract class ProjectDataContextToggleAction extends ToggleDockingAction {

	public ProjectDataContextToggleAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public final boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext instanceof ProjectDataContext)) {
			return false;
		}

		ProjectDataContext context = (ProjectDataContext) actionContext;
		return isEnabledForContext(context);
	}

	/**
	 * Signals that this action can work on normal project data, as well as transient data. 
	 * Transient data is that which will appear in a temporary project dialog.
	 * 
	 * @return true if this action works on transient project data
	 */
	protected boolean supportsTransientProjectData() {
		return false;
	}

	protected boolean isEnabledForContext(ProjectDataContext context) {
		return context.hasOneOrMoreFilesAndFolders();
	}

	@Override
	public final void actionPerformed(ActionContext context) {
		actionPerformed((ProjectDataContext) context);
	}

	protected abstract void actionPerformed(ProjectDataContext context);

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof ProjectDataContext)) {
			return false;
		}
		return isValidContext((ProjectDataContext) context);
	}

	protected boolean isValidContext(ProjectDataContext context) {
		return true;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof ProjectDataContext)) {
			return false;
		}
		return isAddToPopup((ProjectDataContext) context);
	}

	protected boolean isAddToPopup(ProjectDataContext context) {
		return isEnabledForContext(context);
	}

}
