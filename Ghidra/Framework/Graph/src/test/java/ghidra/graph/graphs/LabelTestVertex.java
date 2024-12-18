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
package ghidra.graph.graphs;

import java.awt.Dimension;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import generic.theme.GThemeDefaults.Colors.Palette;

/**
 * A test vertex that renders using a {@link JLabel}.
 */
public class LabelTestVertex extends AbstractTestVertex {

	private JLabel label;

	public LabelTestVertex(String name) {
		super(name);
	}

	@Override
	public JComponent getComponent() {
		if (label == null) {
			label = new GDLabel();
			label.setText(getName());
			label.setPreferredSize(new Dimension(50, 50));
			label.setBackground(Palette.GOLD);
			label.setOpaque(true);
			label.setBorder(BorderFactory.createRaisedBevelBorder());
			label.setHorizontalAlignment(SwingConstants.CENTER);
		}
		return label;
	}

}
