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
package ghidra.app.plugin.core.debug.event;

import ghidra.dbg.target.TargetObject;
import ghidra.framework.plugintool.PluginEvent;

/**
 * Plugin event class for notification of objects being focused in a connected debugger.
 */
public class ModelObjectFocusedPluginEvent extends PluginEvent {
	static final String NAME = "Object Focused";

	private final TargetObject focus;

	/**
	 * Construct a new plugin event.
	 * 
	 * @param source name of the plugin that created this event
	 * @param focusRef the object (ref) associated with this event
	 */
	public ModelObjectFocusedPluginEvent(String source, TargetObject focus) {
		super(source, NAME);
		this.focus = focus;
	}

	/**
	 * Return the new focused object ref. Should never be null.
	 * 
	 * @return the focused object ref
	 */
	public TargetObject getFocus() {
		return focus;
	}
}
