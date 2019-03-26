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

public abstract class DomainFileProviderContextAction extends DockingAction {

	public DomainFileProviderContextAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public final boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext instanceof DomainFileProvider)) {
			return false;
		}
		DomainFileProvider context = (DomainFileProvider) actionContext;
		return isEnabledForContext(context);
	}

	protected boolean isEnabledForContext(DomainFileProvider context) {
		return context.getFileCount() > 0;
	}

	@Override
	public final void actionPerformed(ActionContext context) {
		actionPerformed((DomainFileProvider) context);
	}

	protected abstract void actionPerformed(DomainFileProvider context);

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof DomainFileProvider)) {
			return false;
		}
		return isValidContext((DomainFileProvider) context);
	}

	protected boolean isValidContext(DomainFileProvider context) {
		return true;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DomainFileProvider)) {
			return false;
		}
		return isAddToPopup((DomainFileProvider) context);
	}

	protected boolean isAddToPopup(DomainFileProvider context) {
		return isEnabledForContext(context);
	}

}
