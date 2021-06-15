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

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingType;

public abstract class NavigatableContextAction extends DockingAction {

	public NavigatableContextAction(String name, String owner) {
		super(name, owner);
		setSupportsDefaultToolContext(true);
	}

	public NavigatableContextAction(String name, String owner, KeyBindingType type) {
		super(name, owner, type);
		setSupportsDefaultToolContext(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (context instanceof NavigatableActionContext) {
			return isEnabledForContext((NavigatableActionContext) context);
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof NavigatableActionContext) {
			actionPerformed((NavigatableActionContext) context);
		}
	}

	@Override
	public final boolean isValidContext(ActionContext context) {
		return context instanceof NavigatableActionContext;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof NavigatableActionContext)) {
			return false;
		}
		return isAddToPopup((NavigatableActionContext) context);
	}

	protected boolean isEnabledForContext(NavigatableActionContext context) {
		// assume that all Navigatable context actions require a valid program location
		return context.getLocation() != null;
	}

	protected boolean isAddToPopup(NavigatableActionContext context) {
		return isEnabledForContext(context);
	}

	protected abstract void actionPerformed(NavigatableActionContext context);
}
