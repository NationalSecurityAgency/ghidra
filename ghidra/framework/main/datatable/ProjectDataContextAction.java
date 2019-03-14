/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

public abstract class ProjectDataContextAction extends DockingAction {

	public ProjectDataContextAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public final boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext instanceof ProjectDataActionContext)) {
			return false;
		}
		ProjectDataActionContext context = (ProjectDataActionContext) actionContext;
		return isEnabledForContext(context);
	}

	protected boolean isEnabledForContext(ProjectDataActionContext context) {
		return context.hasOneOrMoreFilesAndFolders();
	}

	@Override
	public final void actionPerformed(ActionContext context) {
		actionPerformed((ProjectDataActionContext) context);
	}

	protected abstract void actionPerformed(ProjectDataActionContext context);

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof ProjectDataActionContext)) {
			return false;
		}
		return isValidContext((ProjectDataActionContext) context);
	}

	protected boolean isValidContext(ProjectDataActionContext context) {
		return true;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof ProjectDataActionContext)) {
			return false;
		}
		return isAddToPopup((ProjectDataActionContext) context);
	}

	protected boolean isAddToPopup(ProjectDataActionContext context) {
		return isEnabledForContext(context);
	}

}
