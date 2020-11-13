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
package docking.action.builder;

import docking.ActionContext;
import docking.action.ToggleDockingAction;

/** 
 * Builder for {@link ToggleDockingAction}s
 */
public class ToggleActionBuilder extends
		AbstractActionBuilder<ToggleDockingAction, ActionContext, ToggleActionBuilder> {

	/**
	 * The initial toggle state for the action
	 */
	private boolean select;

	/**
	 * Builder constructor
	 * @param name the name of the action to be built
	 * @param owner the owner of the action to be build
	 */
	public ToggleActionBuilder(String name, String owner) {
		super(name, owner);
	}

	@Override
	protected ToggleActionBuilder self() {
		return this;
	}

	@Override
	public ToggleDockingAction build() {
		validate();
		ToggleDockingAction action =
			new ToggleDockingAction(name, owner, keyBindingType) {
				@Override
				public void actionPerformed(ActionContext context) {
					actionCallback.accept(context);
				}
			};
		decorateAction(action);
		action.setSelected(select);
		return action;
	}

	/**
	 * Configure the initial select state for the toggle action.
	 * @param b the initial select state
	 * 
	 * @return self Builder (for chaining)
	 */
	public ToggleActionBuilder selected(boolean b) {
		this.select = b;
		return this;
	}

}
