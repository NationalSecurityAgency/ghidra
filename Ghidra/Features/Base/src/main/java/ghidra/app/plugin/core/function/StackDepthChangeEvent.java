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
package ghidra.app.plugin.core.function;

import java.awt.event.ActionEvent;

class StackDepthChangeEvent extends ActionEvent {
	static final int REMOVE_STACK_DEPTH_CHANGE = 0;
	static final int UPDATE_STACK_DEPTH_CHANGE = 1;
	
	private int stackDepthChange;

	public StackDepthChangeEvent(Object source, int id, String command, int stackDepthChange) {
		super(source, id, command);
		this.stackDepthChange = stackDepthChange;
	}
	
	int getStackDepthChange() {
		return stackDepthChange;
	}
	
}
