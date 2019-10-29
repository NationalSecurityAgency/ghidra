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
package ghidra.app.plugin.core.overview.entropy;

import java.awt.*;

import javax.swing.BorderFactory;
import javax.swing.JPanel;

/**
 * Panel for display the Entropy color legend.
 */
public class LegendPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private PalettePanel palettePanel = new PalettePanel(30);
	private KnotLabelPanel knotPanel = new KnotLabelPanel(30);

	public LegendPanel() {
		super(new BorderLayout());
		add(buildHeader(), BorderLayout.NORTH);
		add(palettePanel, BorderLayout.WEST);
		add(knotPanel, BorderLayout.CENTER);
		setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
	}

	private Component buildHeader() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0));
		return panel;
	}

	@Override
	public Dimension getPreferredSize() {
		return new Dimension(210, 300);
	}

	public void setPalette(Palette pal) {
		palettePanel.setPalette(pal);
		knotPanel.setPalette(pal);
	}

}
