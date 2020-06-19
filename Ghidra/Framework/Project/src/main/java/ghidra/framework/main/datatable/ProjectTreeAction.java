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
import docking.action.DockingAction;
import ghidra.framework.main.datatree.ProjectTreeContext;

public abstract class ProjectTreeAction extends DockingAction {

	public ProjectTreeAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public final boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext instanceof ProjectTreeContext)) {
			return false;
		}

		ProjectTreeContext context = (ProjectTreeContext) actionContext;
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

	protected boolean isEnabledForContext(ProjectTreeContext context) {
		return context.hasOneOrMoreFilesAndFolders();
	}

	@Override
	public final void actionPerformed(ActionContext context) {
		actionPerformed((ProjectTreeContext) context);
	}

	protected abstract void actionPerformed(ProjectTreeContext context);

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof ProjectTreeContext)) {
			return false;
		}
		return isValidContext((ProjectTreeContext) context);
	}

	protected boolean isValidContext(ProjectTreeContext context) {
		return true;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!isEnabledForContext(context)) {
			return false;
		}
		return isAddToPopup((ProjectTreeContext) context);
	}

	protected boolean isAddToPopup(ProjectTreeContext context) {
		return isEnabledForContext(context);
	}

}
