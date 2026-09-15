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
package docking.widgets.gtreetable;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.Border;

import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.GColumnRenderer;

public class GTreeTableCellRenderer<T extends GTreeTableNode> extends GTableCellRenderer
		implements GColumnRenderer<T> {
	private class ExpandCollapseBorder implements Border {
		GTreeTableNode node;

		ExpandCollapseBorder(GTreeTableNode node) {
			super();
			this.node = node;
		}

		@Override
		public Insets getBorderInsets(final Component c) {
			return insets;
		}

		@Override
		public boolean isBorderOpaque() {
			return false;
		}

		@Override
		public void paintBorder(final Component c, final Graphics g, final int x, final int y,
				final int width, final int height) {
			if (node.hasVisibleChildren()) {
				final JLabel renderer = new JLabel("", SwingConstants.RIGHT);
				renderer.setIcon(node.isExpanded() ? expandedIcon : collapsedIcon);
				renderer.setSize(insets.left, height);
				renderer.paint(g);
			}
		}
	}

	private static final int PIXELS_PER_LEVEL = 16;
	private final Insets insets = new Insets(0, 0, 0, 0);
	private final Icon expandedIcon;
	private final Icon collapsedIcon;
	private final int maxIconWidth;

	public GTreeTableCellRenderer() {
		expandedIcon = UIManager.getIcon("Tree.expandedIcon");
		collapsedIcon = UIManager.getIcon("Tree.collapsedIcon");
		final int expandedWidth = expandedIcon == null ? 0 : expandedIcon.getIconWidth();
		final int collapsedWidth = collapsedIcon == null ? 0 : collapsedIcon.getIconWidth();
		maxIconWidth = Math.max(expandedWidth, collapsedWidth);
	}

	@Override
	public String getFilterString(GTreeTableNode t, Settings settings) {
		return t.getTreeData();
	}

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		final JLabel renderer = (JLabel) super.getTableCellRendererComponent(data);

		if (data.getRowObject() instanceof final GTreeTableNode c) {
			final boolean selected = data.isSelected();
			final JTable table = data.getTable();

			renderer.setForeground(
				selected ? table.getSelectionForeground() : table.getForeground());
			renderer.setBackground(selected ? table.getSelectionBackground()
					: getAlternatingBackgroundColor(table, data.getRowViewIndex()));
			renderer.setFont(table.getFont());
			renderer.setToolTipText(c.getName());
			insets.left = maxIconWidth + (c.getLevel() * PIXELS_PER_LEVEL);
			renderer.setIcon(c.getIcon());
			renderer.setText(c.getTreeData());
			renderer.setBorder(new ExpandCollapseBorder(c));
		}
		return renderer;

	}

	/**
	 * Check if x position is in the expand icon space
	 *
	 * @param node
	 * 		Node to determine how indented the expand icon is
	 * @param x
	 * 		X coordinate to check against
	 * @return true/false if X coordinate is in expand icon space
	 */
	public boolean inExpandIcon(GTreeTableNode node, int x) {
		final int iconStart = (node.getLevel() * PIXELS_PER_LEVEL);
		return ((x > iconStart) && (x < (iconStart + maxIconWidth)));
	}
}
