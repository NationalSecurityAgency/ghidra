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

import java.awt.Graphics;
import java.awt.event.MouseEvent;

import javax.swing.JPanel;
import javax.swing.ToolTipManager;

/**
 * Panel to display markers.  Normally placed to the left hand side
 * of the scrolled field panel.
 */
public class MarkerPanel extends JPanel {

	private MarkerManager manager;

	MarkerPanel(MarkerManager manager) {
		super();
		this.manager = manager;

		ToolTipManager.sharedInstance().registerComponent(this);
	}

	@Override
	protected void paintComponent(Graphics g) {
		super.paintComponent(g);

		manager.paintMarkers(g);
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		return manager.getTooltip(event);
	}
}
