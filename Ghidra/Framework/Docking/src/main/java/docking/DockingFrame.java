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

import javax.swing.JFrame;

import ghidra.util.bean.GGlassPane;

/**
 * Base JFrame to be used by the root window and detached windows if they are using frames
 *
 * Also fixed:
 * <ol>
 *  <li>Swing problem of setting bounds before the frame is visible causes slow paints
 * 	if the bounds position is not on the primary display, </li>
 * </ol>
 */
public class DockingFrame extends JFrame {

	public DockingFrame(String name) {
		super(name);
		GGlassPane ghidraGlassPane = new GGlassPane();
		setGlassPane(ghidraGlassPane);
		ghidraGlassPane.setVisible(true);
	}

	@Override
	public String toString() {
		return getTitle();
	}
}
