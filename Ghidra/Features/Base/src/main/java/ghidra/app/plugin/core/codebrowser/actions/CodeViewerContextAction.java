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
package ghidra.app.plugin.core.codebrowser.actions;

import java.util.Set;

import docking.ActionContext;
import docking.action.DockingAction;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;

public abstract class CodeViewerContextAction extends DockingAction {

	public CodeViewerContextAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}
		return isEnabledForContext((CodeViewerActionContext) context);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}
		return isValidContext((CodeViewerActionContext) context);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}
		return isAddToPopup((CodeViewerActionContext) context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		actionPerformed((CodeViewerActionContext) context);
	}

	protected boolean isAddToPopup(CodeViewerActionContext context) {
		return isEnabledForContext(context);
	}

	protected boolean isValidContext(CodeViewerActionContext context) {
		return true;
	}

	protected boolean isEnabledForContext(CodeViewerActionContext context) {
		return true;
	}

	protected void actionPerformed(CodeViewerActionContext context) {

	}

	@Override
	public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
		for (Class<?> class1 : contextTypes) {
			if (CodeViewerActionContext.class.isAssignableFrom(class1)) {
				return true;
			}
		}
		return false;
	}

}
