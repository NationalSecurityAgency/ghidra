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
package ghidra.app.plugin.core.debug.gui.stack;

import java.awt.Component;

import docking.ActionContext;

public class DebuggerStackActionContext extends ActionContext {

	private final StackFrameRow frame;

	public DebuggerStackActionContext(DebuggerStackProvider provider, StackFrameRow frame,
			Component sourceComponent) {
		super(provider, frame, sourceComponent);
		this.frame = frame;
	}

	public StackFrameRow getFrame() {
		return frame;
	}
}
