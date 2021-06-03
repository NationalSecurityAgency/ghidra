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

public abstract class ProgramContextAction extends DockingAction {

	public ProgramContextAction(String name, String owner) {
		super(name, owner);
	}
	
	@Override
	public boolean isEnabledForContext(ActionContext actionContext) {
		if (!(actionContext instanceof ProgramActionContext)) {
			return false;
		}
		ProgramActionContext context = (ProgramActionContext)actionContext;
		if (context.getProgram() == null) {
			return false;
		}
		return isEnabledForContext(context);
	}

	@Override
	public final void actionPerformed(ActionContext context) {
		actionPerformed((ProgramActionContext)context);
	}
	
	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof ProgramActionContext)) {
			return false;
		}
		return isValidContext((ProgramActionContext)context);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof ProgramActionContext)) {
			return false;
		}
		return isAddToPopup((ProgramActionContext)context);
	}
	
	protected boolean isAddToPopup(ProgramActionContext context) {
		return isEnabledForContext( context );
	}
	
	protected boolean isValidContext(ProgramActionContext context) {
		return true;
	}
	
	protected boolean isEnabledForContext(ProgramActionContext context) {
		return true;
	}
	protected abstract void actionPerformed(ProgramActionContext programContext);
	
	protected final void actionPerformed(ProgramActionContext programContext, ActionContext actionContext) {
		
	}

}
