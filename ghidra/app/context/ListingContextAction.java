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


import java.util.Set;

import docking.ActionContext;
import docking.action.DockingAction;

public abstract class ListingContextAction extends DockingAction {
	
    public ListingContextAction(String name, String owner) {
        this(name, owner, true);
    }
    
	public ListingContextAction(String name, String owner, boolean isKeyBindingManaged) {
		super(name, owner, isKeyBindingManaged);
	}
	
	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof ListingActionContext)) {
			return false;
		}
		return isEnabledForContext((ListingActionContext)context);
	}

	@Override
	public boolean isValidContext(ActionContext context) {
		if (!(context instanceof ListingActionContext)) {
			return false;
		}
		return isValidContext((ListingActionContext)context);
	}
	 
	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof ListingActionContext)) {
			return false;
		}
		return isAddToPopup((ListingActionContext)context);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		actionPerformed((ListingActionContext)context);
	}

	protected boolean isAddToPopup(ListingActionContext context) {
		return isEnabledForContext( context );
	}
	
	protected boolean isValidContext(ListingActionContext context) {
		return true;
	}
	
	protected boolean isEnabledForContext(ListingActionContext context) {
		return true;
	}

	protected void actionPerformed(ListingActionContext context) {
		
	}
	
	@Override
	public boolean shouldAddToWindow(boolean isMainWindow, Set<Class<?>> contextTypes) {
		for (Class<?> class1 : contextTypes) {
			if (ListingActionContext.class.isAssignableFrom(class1)) {
				return true;
			}
		}
		return false;
	}

}
