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
package docking.action;

import docking.ActionContext;

/**
 * This class is used simplify DockingAction logic for actions that work with
 * specific {@link ActionContext}.  It automatically checks the ActionContext
 * and disables/invalidates/prevent popup, if the context is not the expected
 * type.  If the context type is correct, it casts the context to the expected
 * specific type and calls the equivalent method with the ActionContext already
 * cast to the expected type.
 *
 * @param <T> The expected {@link ActionContext} type
 */

public abstract class ContextSpecificAction<T> extends DockingAction {
	private Class<T> contextClass;

	/**
	 * Constructor
	 * @param name the name of the action.
	 * @param owner the owner of the action.
	 * @param contextClass the class of the expected ActionContext type.
	 */
	public ContextSpecificAction(String name, String owner, Class<T> contextClass) {
		super(name, owner);
		this.contextClass = contextClass;
	}

	@Override
	public boolean isEnabledForContext(ActionContext actionContext) {
		if (contextClass.isInstance(actionContext)) {
			return isEnabledForContext(contextClass.cast(actionContext));
		}
		return false;
	}

	@Override
	public boolean isValidContext(ActionContext actionContext) {
		if (contextClass.isInstance(actionContext)) {
			return isValidContext(contextClass.cast(actionContext));
		}
		return false;
	}

	@Override
	public boolean isAddToPopup(ActionContext actionContext) {
		if (contextClass.isInstance(actionContext)) {
			return isAddToPopup(contextClass.cast(actionContext));
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext actionContext) {
		actionPerformed(contextClass.cast(actionContext));

	}

	/**
	 * The actionPerformed method with a more specific ActionContext. 
	 * See {@link DockingAction#actionPerformed(ActionContext)}
	 * 
	 * @param context the more specific {@link ActionContext}
	 */
	abstract protected void actionPerformed(T context);

	protected boolean isAddToPopup(T context) {
		return isEnabledForContext(context);
	}

	protected boolean isEnabledForContext(T context) {
		return true;
	}

	protected boolean isValidContext(T context) {
		return true;
	}
}
