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

import java.awt.Dimension;

import javax.swing.JFrame;

import ghidra.util.bean.GGlassPane;

/**
 * Base frame used by the root window and detached windows
 */
public class DockingFrame extends JFrame {

	// fairly arbitrary values
	private static final int MIN_WIDTH = 200;
	private static final int MIN_HEIGHT = 200;

	private boolean isTransient;

	public DockingFrame(String name) {
		super(name);

		GGlassPane ghidraGlassPane = new GGlassPane();
		setGlassPane(ghidraGlassPane);
		ghidraGlassPane.setVisible(true);

		// Set a minimum size to prevent losing windows made too small under error conditions 
		setMinimumSize(new Dimension(MIN_WIDTH, MIN_HEIGHT));
	}

	/**
	 * Marks this frame as transient.  A transient frame is one that is shown temporarily.
	 */
	public void setTransient() {
		this.isTransient = true;
	}

	/**
	 * Returns whether this frame is transient.  A transient frame is one that is shown temporarily.
	 * @return true if transient
	 */
	public boolean isTransient() {
		return isTransient;
	}

	@Override
	public String toString() {
		return getTitle() + (isTransient ? " - transient" : "") + " (" +
			System.identityHashCode(this) + ")";
	}
}
