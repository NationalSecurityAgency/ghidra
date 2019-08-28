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
package ghidra.app.context;

import java.util.Set;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingType;

public abstract class NavigatableContextAction extends DockingAction {

	public NavigatableContextAction(String name, String owner) {
		super(name, owner);
	}

	public NavigatableContextAction(String name, String owner, KeyBindingType type) {
		super(name, owner, type);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof NavigatableActionContext)) {
			return false;
		}
		return isEnabledForContext((NavigatableActionContext) context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		actionPerformed((NavigatableActionContext) context);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof NavigatableActionContext)) {
			return false;
		}
		return isValidContext((NavigatableActionContext) context);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof NavigatableActionContext)) {
			return false;
		}
		return isAddToPopup((NavigatableActionContext) context);
	}

	protected boolean isValidContext(NavigatableActionContext context) {
		return true;
	}

	protected boolean isEnabledForContext(NavigatableActionContext context) {
		return true;
	}

	protected boolean isAddToPopup(NavigatableActionContext context) {
		return isEnabledForContext(context);
	}

	protected void actionPerformed(NavigatableActionContext context) {
		// optional for subclasses
	}

	@Override
	public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
		for (Class<?> class1 : contextTypes) {
			if (NavigatableActionContext.class.isAssignableFrom(class1)) {
				return true;
			}
		}
		return false;
	}
}
