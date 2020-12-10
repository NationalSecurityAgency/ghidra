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
package ghidra.app.plugin.core.debug.gui.objects;

import ghidra.framework.plugintool.PluginEvent;

public class ObjectUpdatedEvent extends PluginEvent {

	private ObjectContainer object;

	public ObjectUpdatedEvent(ObjectContainer object) {
		super(object.getName(), "update");
		this.object = object;
	}

	public ObjectContainer getObject() {
		return object;
	}

}
