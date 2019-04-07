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
package ghidra.app.context;

import docking.ActionContext;
import docking.action.DockingAction;

public abstract class ProgramSymbolContextAction extends DockingAction {

	public ProgramSymbolContextAction(String name, String owner) {
		super(name, owner);
	}

	@Override
	public final boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext instanceof ProgramSymbolActionContext)) {
			return false;
		}
		ProgramSymbolActionContext context = (ProgramSymbolActionContext) actionContext;
		if (context.getProgram() == null) {
			return false;
		}
		return isEnabledForContext(context);
	}

	@Override
	public final void actionPerformed(ActionContext context) {
		actionPerformed((ProgramSymbolActionContext) context);
	}

	@Override
	public final boolean isValidContext(ActionContext context) {
		if (!(context instanceof ProgramSymbolActionContext)) {
			return false;
		}
		return isValidContext((ProgramSymbolActionContext) context);
	}

	@Override
	public final boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof ProgramSymbolActionContext)) {
			return false;
		}
		return isAddToPopup((ProgramSymbolActionContext) context);
	}

	protected boolean isAddToPopup(ProgramSymbolActionContext context) {
		return isEnabledForContext(context);
	}

	protected boolean isValidContext(ProgramSymbolActionContext context) {
		return true;
	}

	protected boolean isEnabledForContext(ProgramSymbolActionContext context) {
		return context.getSymbolCount() != 0;
	}

	protected abstract void actionPerformed(ProgramSymbolActionContext context);

}
