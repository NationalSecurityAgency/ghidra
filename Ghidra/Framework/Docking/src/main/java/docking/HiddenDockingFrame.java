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
package docking;

/**
 * Hack to fix:
 * <ol>
 *  <li>JFrames cannot be invisible</li>
 * </ol>
 */
public class HiddenDockingFrame extends DockingFrame {

	private boolean showingAllowed;

	public HiddenDockingFrame(String name) {
		super(name);
	}

	void setShowingAllowed(boolean showingAllowed) {
		this.showingAllowed = showingAllowed;
	}

	@SuppressWarnings("deprecation")
	@Override
	public void show() {
		// overridden to make sure only some clients can show this frame
		if (showingAllowed) {
			super.show();
		}
	}

}
