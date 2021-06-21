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
import ghidra.app.plugin.core.debug.gui.DebuggerResources.TrackLocationAction;
import ghidra.framework.plugintool.Plugin;

public interface DebuggerTrackLocationAction extends TrackLocationAction {
	// TODO: Update the action when new specs enter the class path?
	static MultiStateActionBuilder<LocationTrackingSpec> builder(Plugin owner) {
		MultiStateActionBuilder<LocationTrackingSpec> builder = TrackLocationAction.builder(owner);
		builder.toolBarGroup(owner.getName());
		builder.performActionOnButtonClick(true);
		for (LocationTrackingSpec spec : LocationTrackingSpec.allSpecs().values()) {
			builder.addState(spec.getMenuName(), spec.getMenuIcon(), spec);
		}
		return builder;
	}
}
