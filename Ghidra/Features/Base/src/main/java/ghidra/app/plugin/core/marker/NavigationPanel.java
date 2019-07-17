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
package ghidra.app.plugin.core.marker;

import java.awt.Graphics;
import java.awt.event.*;

import javax.swing.JPanel;

/**
 * Panel to display an overview of all markers placed within a scrolled
 * FieldPanel.
 * Normally placed to the right of the scrolled panel.
 */
public class NavigationPanel extends JPanel {

	private MarkerManager manager;

	NavigationPanel(MarkerManager manager) {
		super();
		this.manager = manager;
		init();
	}

	private void init() {
		// process mouse events
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {

				if ((e.getModifiers() & InputEvent.BUTTON1_MASK) != 0) {
					manager.navigateTo(e.getX(), e.getY());
				}
			}

		});
	}

	/**
	 * @see javax.swing.JComponent#paintComponent(Graphics)
	 */
	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);
		manager.paintNavigation(g, this);
	}

}
