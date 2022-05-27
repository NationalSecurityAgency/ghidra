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
package ghidra.app.plugin.core.marker;

import java.awt.Dimension;
import java.awt.Graphics;
import java.awt.event.*;

import javax.swing.JPanel;

import docking.widgets.fieldpanel.FieldPanel;
import ghidra.app.nav.Navigatable;
import ghidra.app.util.viewer.util.AddressIndexMap;
import ghidra.program.model.listing.Program;

/**
 * Panel to display an overview of all markers placed within a scrolled {@link FieldPanel}. Normally
 * placed to the right of the scrolled panel.
 */
public class NavigationPanel extends JPanel {

	private MarkerManager manager;

	private Navigatable navigatable;
	private Program program;
	private AddressIndexMap addrMap;

	NavigationPanel(MarkerManager manager) {
		super();
		this.manager = manager;

		this.setPreferredSize(new Dimension(16, 1));

		init();
	}

	private void init() {
		// process mouse events
		addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if ((e.getModifiersEx() & InputEvent.BUTTON1_DOWN_MASK) != 0) {
					manager.navigateTo(navigatable, program, e.getX(), e.getY(), getViewHeight(),
						addrMap);
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
		paintNavigation(g);
	}

	void paintNavigation(Graphics g) {
		manager.paintNavigation(program, g, this, addrMap);
	}

	void setNavigatable(Navigatable navigatable) {
		this.navigatable = navigatable;
	}

	void setProgram(Program program, AddressIndexMap map) {
		this.program = program;
		this.addrMap = map;
	}

	public int getViewHeight() {
		return getHeight() - MarkerSetImpl.MARKER_HEIGHT;
	}
}
