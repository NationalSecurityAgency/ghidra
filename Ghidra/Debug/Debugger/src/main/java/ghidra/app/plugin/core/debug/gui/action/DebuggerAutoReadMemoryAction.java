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
package ghidra.app.plugin.core.debug.gui.action;

import docking.action.builder.MultiStateActionBuilder;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.AutoReadMemoryAction;
import ghidra.framework.plugintool.Plugin;

public interface DebuggerAutoReadMemoryAction extends AutoReadMemoryAction {
	// TODO: Update the action when new specs enter the class path?
	static MultiStateActionBuilder<AutoReadMemorySpec> builder(Plugin owner) {
		MultiStateActionBuilder<AutoReadMemorySpec> builder = AutoReadMemoryAction.builder(owner);
		builder.toolBarGroup(NAME);
		builder.performActionOnButtonClick(true);
		for (AutoReadMemorySpec spec : AutoReadMemorySpec.allSpecs().values()) {
			builder.addState(spec.getMenuName(), spec.getMenuIcon(), spec);
		}
		return builder;
	}
}
