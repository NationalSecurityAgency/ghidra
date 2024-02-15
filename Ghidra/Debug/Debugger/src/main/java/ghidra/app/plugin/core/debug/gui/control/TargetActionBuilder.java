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
package ghidra.app.plugin.core.debug.gui.control;

import docking.ActionContext;
import docking.action.builder.AbstractActionBuilder;
import ghidra.debug.api.target.ActionName;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;

class TargetActionBuilder
		extends AbstractActionBuilder<TargetDockingAction, ActionContext, TargetActionBuilder> {
	private final PluginTool tool;

	private ActionName action;
	private String defaultDescription;

	public TargetActionBuilder(String name, Plugin owner) {
		super(name, owner.getName());
		this.tool = owner.getTool();
	}

	@Override
	protected TargetActionBuilder self() {
		return this;
	}

	@Override
	protected void validate() {
		super.validate();
		if (action == null) {
			throw new IllegalStateException(
				"Can't build a " + TargetDockingAction.class.getSimpleName() +
					" without an action name");
		}
	}

	public TargetActionBuilder action(ActionName action) {
		this.action = action;
		return self();
	}

	public TargetActionBuilder defaultDescription(String defaultDescription) {
		this.defaultDescription = defaultDescription;
		return self();
	}

	@Override
	public TargetDockingAction build() {
		onAction(ctx -> {
			// Make the super.validate() hush
		});
		validate();
		TargetDockingAction result = new TargetDockingAction(name, owner, keyBindingType, tool,
			action, defaultDescription);
		decorateAction(result);
		return result;
	}
}
