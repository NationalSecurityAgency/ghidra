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

public abstract class DomainFileProviderContextAction extends DockingAction {

	public DomainFileProviderContextAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public final boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext instanceof DomainFileContext)) {
			return false;
		}

		DomainFileContext context = (DomainFileContext) actionContext;
		if (context.isBusy()) {
			return false;
		}

		return isEnabledForContext(context);
	}

	protected boolean isEnabledForContext(DomainFileContext context) {
		return context.getFileCount() > 0;
	}

	@Override
	public final void actionPerformed(ActionContext context) {
		actionPerformed((DomainFileContext) context);
	}

	protected abstract void actionPerformed(DomainFileContext context);

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof DomainFileContext)) {
			return false;
		}
		return isValidContext((DomainFileContext) context);
	}

	protected boolean isValidContext(DomainFileContext context) {
		return true;
	}

	@Override
	public final boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DomainFileContext)) {
			return false;
		}

		DomainFileContext fileContext = (DomainFileContext) context;
		if (fileContext.isBusy()) {
			return false;
		}
		return isAddToPopup(fileContext);
	}

	protected boolean isAddToPopup(DomainFileContext context) {
		return isEnabledForContext(context);
	}

}
