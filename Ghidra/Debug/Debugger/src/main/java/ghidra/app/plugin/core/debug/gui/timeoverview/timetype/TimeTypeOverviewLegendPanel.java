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
package ghidra.app.plugin.core.debug.gui.timeoverview.timetype;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;

import docking.widgets.label.GLabel;
import ghidra.util.layout.PairLayout;

/**
 * A component for displaying the color legend for the {@link TimeTypeOverviewColorService}
 */
public class TimeTypeOverviewLegendPanel extends JPanel {
	private static Dimension COLOR_SIZE = new Dimension(15, 15);
	private TimeTypeOverviewColorService colorService;

	public TimeTypeOverviewLegendPanel(TimeTypeOverviewColorService colorService) {
		this.colorService = colorService;
		setLayout(new PairLayout(4, 10));
		setBorder(BorderFactory.createEmptyBorder(4, 20, 4, 30));
		buildLegend();
	}

	/**
	 * Kick to repaint when the colors have changed.
	 */
	public void updateColors() {
		repaint();
	}

	private void buildLegend() {
		removeAll();
		TimeType[] values = TimeType.values();
		for (TimeType timeType : values) {
			JPanel panel = new ColorPanel(timeType);
			add(panel);
			add(new GLabel(timeType.getDescription()));
		}
	}

	private class ColorPanel extends JPanel {
		private TimeType type;

		ColorPanel(TimeType type) {
			this.type = type;
			setPreferredSize(COLOR_SIZE);
			addMouseListener(new MouseAdapter() {
				@Override
				public void mousePressed(MouseEvent e) {
					Color newColor =
						JColorChooser.showDialog(ColorPanel.this, "Select Color", getBackground());
					colorService.setColor(type, newColor);
				}
			});
		}

		@Override
		protected void paintComponent(Graphics g) {
			setBackground(colorService.getColor(type));
			super.paintComponent(g);
		}

	}

}
