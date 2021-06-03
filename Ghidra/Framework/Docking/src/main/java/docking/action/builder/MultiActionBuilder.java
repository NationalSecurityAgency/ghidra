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

import java.util.Collections;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingActionIf;
import docking.menu.MultiActionDockingAction;

/** 
 * Builder for {@link MultiActionDockingAction}
 */
public class MultiActionBuilder
		extends AbstractActionBuilder<MultiActionDockingAction, ActionContext, MultiActionBuilder> {
	/**
	 * List of actions for the the MultActionDockingAction
	 */
	private List<DockingActionIf> actionList = Collections.emptyList();
	/**
	 * determines if the the main action is invokable
	 */
	private boolean performActionOnButtonClick = true;

	/**
	 * Builder constructor
	 * @param name the name of the action to be built
	 * @param owner the owner of the action to be build
	 */
	public MultiActionBuilder(String name, String owner) {
		super(name, owner);
	}

	@Override
	protected MultiActionBuilder self() {
		return this;
	}

	@Override
	public MultiActionDockingAction build() {
		validate();
		MultiActionDockingAction action = new MultiActionDockingAction(name, owner) {
			@Override
			public void actionPerformed(ActionContext context) {
				actionCallback.accept(context);
			}
		};
		decorateAction(action);
		action.setActions(actionList);
		action.setPerformActionOnButtonClick(performActionOnButtonClick);
		return action;
	}

	/**
	 * Configure a {@link List} of {@link DockingActionIf} to provide to the {@link MultiActionDockingAction}
	 * @param list a {@link List} of {@link DockingActionIf} to provide to the {@link MultiActionDockingAction}
	 * @return this MultiActionDockingActionBuilder (for chaining)
	 */
	public MultiActionBuilder withActions(List<DockingActionIf> list) {
		this.actionList = list;
		for (DockingActionIf action : actionList) {
			if (action.getMenuBarData() == null) {
				throw new IllegalStateException(
					"actions in the actionList must have MenuBarData defined");
			}
		}
		return self();
	}

	/**
	 * Configure whether to perform actions on a button click. 
	 * See {@link MultiActionDockingAction#setPerformActionOnButtonClick(boolean)}
	 * 
	 * @param b true if the main action is invokable
	 * @return this MultiActionDockingActionBuilder (for chaining)
	 */
	public MultiActionBuilder performActionOnButtonClick(boolean b) {
		this.performActionOnButtonClick = b;
		return self();
	}

	@Override
	protected void validate() {
		// if the MultiAction performs an action when the main button is presseed, make sure that 
		// an action callback has been defined in before building (which is what super validate
		// does). Otherwise, don't force the client to define an action callback if it won't be used.
		if (performActionOnButtonClick) {
			super.validate();
		}
		if (actionList == null) {
			throw new IllegalStateException("No ActionList has been set");
		}
	}

}
