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
package docking.theme.gui;

import static docking.theme.gui.ColorSorter.*;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.action.ActionContextProvider;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.theme.*;
import ghidra.util.WebColors;

/**
 * Tree for showing colors organized by similar colors and reference relationships. This was
 * built as a developer aid to help consolidate similar colors in Ghidra. This may be removed
 * at any time.
 */

public class ThemeColorTree extends JPanel implements ActionContextProvider {

	private ColorRootNode root;
	private GTree tree;
	private JComboBox<GroupingStrategy> groupingCombo;
	private JComboBox<ColorSorter> colorSortCombo;
	private ThemeManager themeManager;

	public ThemeColorTree(ThemeManager themeManager) {
		this.themeManager = themeManager;
		buildBinCombo();
		buildSortCombo();
		root = new ColorRootNode();
		tree = new GTree(root);
		setLayout(new BorderLayout());
		add(tree, BorderLayout.CENTER);
		add(buildControls(), BorderLayout.SOUTH);
	}

	private Component buildControls() {
		JPanel panel = new JPanel();
		panel.add(new JLabel("Group By: "));
		panel.add(groupingCombo);
		panel.add(new JLabel("Sort Order: "));
		panel.add(colorSortCombo);
		return panel;
	}

	private Component buildBinCombo() {
		groupingCombo = new JComboBox<>(GroupingStrategy.values());
		groupingCombo.setSelectedItem(GroupingStrategy.BIN_64);
		groupingCombo.addItemListener(this::comboChanged);
		return groupingCombo;
	}

	private void comboChanged(ItemEvent ev) {
		rebuild();
	}

	private Component buildSortCombo() {
		ColorSorter[] sorters = { RGB, RBG, GRB, GBR, BRG, BGR };
		colorSortCombo = new JComboBox<>(sorters);
		colorSortCombo.addItemListener(this::comboChanged);
		return colorSortCombo;
	}

	public void rebuild() {
		root = new ColorRootNode();
		tree.setRootNode(root);
	}

	private class SwatchIcon implements Icon {
		private Color color;
		private Color border;

		SwatchIcon(Color c) {
			this.color = c;
			this.border = GThemeDefaults.Colors.FOREGROUND;
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			g.setColor(color);
			g.fillRect(x, y, 16, 16);
			g.setColor(border);
			g.drawRect(x, y, 16, 16);
		}

		@Override
		public int getIconWidth() {
			return 18;
		}

		@Override
		public int getIconHeight() {
			return 18;
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent e) {
		return null;
	}

	enum GroupingStrategy {
		REF("Reference"),
		SAME_COLORS("Same Color"),
		BIN_8("8 Bins"),
		BIN_64("64 Bins"),
		BIN_512("512 Bins");

		private String name;

		GroupingStrategy(String name) {
			this.name = name;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	private class ColorNode extends GTreeNode {
		protected Color color;
		protected Icon icon;
		private String name;
		protected String displayText;

		ColorNode(Color color) {
			this(color, "");
		}

		ColorNode(Color color, String namePrefix) {
			this.name = namePrefix + getColorString(color);
			this.color = color instanceof GColor ? new Color(color.getRGB()) : color;
			this.icon = new SwatchIcon(color);
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getDisplayText() {
			if (displayText == null) {
				displayText = name;
				int childCount = getChildCount();
				if (childCount > 0) {
					int leafCount = getLeafCount();
					displayText = name + "  (" + childCount + ", " + leafCount + ")";
				}
			}
			return displayText;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return icon;
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}

		public Color getColor() {
			return color;
		}

		protected String getColorString(Color c) {
			String colorName = WebColors.toString(c, false);

			String webColorName = WebColors.toWebColorName(c);
			if (webColorName != null) {
				colorName += " (" + webColorName + ")";
			}
			return colorName;
		}

		public void sort(ColorSorter sorter) {
			if (getChildCount() == 0) {
				return;
			}
			List<GTreeNode> children = new ArrayList<>(getChildren());

			for (GTreeNode node : children) {
				((ColorNode) node).sort(sorter);
			}
			sortChildren(children, sorter);
			setChildren(children);
		}

		protected void sortChildren(List<GTreeNode> nodes, ColorSorter sorter) {
			Collections.sort(nodes,
				(a, b) -> sorter.compare(((ColorNode) a).getColor(), ((ColorNode) b).getColor()));
		}
	}

	private class SameColorGroupNode extends ColorNode {
		SameColorGroupNode(Color color) {
			super(color);
		}

		@Override
		protected void sortChildren(List<GTreeNode> nodes, ColorSorter sorter) {
			Collections.sort(nodes);
		}
	}

	private class ColorValueNode extends ColorNode {

		private ColorValue colorValue;

		public ColorValueNode(ColorValue colorValue) {
			super(new GColor(colorValue.getId()), colorValue.getId() + "  ");
			this.colorValue = colorValue;
		}

		@Override
		public boolean isLeaf() {
			return getChildCount() == 0;
		}

		public boolean isIndirect() {
			return colorValue.isIndirect();
		}

		public String getReferenceId() {
			return colorValue.getReferenceId();
		}

		public String getId() {
			return colorValue.getId();
		}

		@Override
		protected void sortChildren(List<GTreeNode> nodes, ColorSorter sorter) {
			Collections.sort(nodes);
		}
	}

	private class ColorRootNode extends GTreeNode {
		int uniqueColors = 0;

		public ColorRootNode() {
			List<GTreeNode> children = buildChildren();
			setChildren(children);
			uniqueColors = countUniqueColors(children);
			sortChildren();
		}

		private void sortChildren() {
			ColorSorter sorter = (ColorSorter) colorSortCombo.getSelectedItem();

			List<GTreeNode> children = new ArrayList<>(getChildren());
			if (children.isEmpty()) {
				return;
			}
			for (GTreeNode node : children) {
				((ColorNode) node).sort(sorter);
			}

			if (children.get(0) instanceof ColorValueNode) {
				Collections.sort(children);
			}
			else {
				Collections.sort(children, (a, b) -> sorter.compare(((ColorNode) a).getColor(),
					((ColorNode) b).getColor()));
			}
			setChildren(children);

		}

		private int countUniqueColors(List<GTreeNode> children) {
			Iterator<GTreeNode> iterator = iterator(true);
			Set<Color> set = new HashSet<>();
			while (iterator.hasNext()) {
				GTreeNode node = iterator.next();

				if (node instanceof ColorNode colorNode) {
					set.add(colorNode.getColor());
				}
			}
			return set.size();
		}

		private List<GTreeNode> buildChildren() {

			List<ColorValueNode> nodes = new ArrayList<>();
			GThemeValueMap currentValues = themeManager.getCurrentValues();
			List<ColorValue> colors = currentValues.getColors();
			for (ColorValue colorValue : colors) {
				nodes.add(new ColorValueNode(colorValue));
			}

			nodes = organizeByIdRefs(nodes);

			int bins = 1;
			GroupingStrategy grouping = (GroupingStrategy) groupingCombo.getSelectedItem();
			switch (grouping) {
				case REF:
					return new ArrayList<>(nodes);
				case SAME_COLORS:
					List<ColorNode> grouped = groupSameColors(nodes);
					return new ArrayList<>(grouped);
				case BIN_8:
					bins = 8;
					grouped = groupSameColors(nodes);
					List<ColorNode> binned = binColors(grouped, bins);
					return new ArrayList<>(binned);
				case BIN_64:
					bins = 64;
					grouped = groupSameColors(nodes);
					binned = binColors(grouped, bins);
					return new ArrayList<>(binned);
				case BIN_512:
					bins = 512;
					grouped = groupSameColors(nodes);
					binned = binColors(grouped, bins);
					return new ArrayList<>(binned);
				default:
					return new ArrayList<>();
			}
		}

		private List<ColorValueNode> organizeByIdRefs(List<ColorValueNode> nodes) {
			List<ColorValueNode> results = new ArrayList<>();

			Map<String, ColorValueNode> idMap = new HashMap<>();
			for (ColorValueNode node : nodes) {
				idMap.put(node.getId(), node);
			}
			for (ColorValueNode colorNode : nodes) {
				if (colorNode.isIndirect()) {
					String refId = colorNode.getReferenceId();
					ColorValueNode parent = idMap.get(refId);
					if (parent == null) {
						// this implies the user has changed id names and refreshed the tool
						continue;
					}
					parent.addNode(colorNode);
				}
				else {
					results.add(colorNode);
				}
			}
			return results;
		}

		private List<ColorNode> groupSameColors(List<ColorValueNode> nodes) {
			Map<Color, ColorNode> colorMap = new HashMap<>();
			for (ColorNode node : nodes) {
				Color color = node.getColor();
				ColorNode group = colorMap.computeIfAbsent(color, k -> new SameColorGroupNode(k));
				group.addNode(node);
			}
			return new ArrayList<>(colorMap.values());
		}

		private List<ColorNode> binColors(List<ColorNode> nodes, int bins) {
			int shift = computeShift(bins);
			Map<Color, ColorNode> binnedColorMap = new HashMap<>();
			for (ColorNode node : nodes) {
				Color binnedColor = binColor(node, shift);
				ColorNode group =
					binnedColorMap.computeIfAbsent(binnedColor, k -> new ColorNode(k, "Bin "));
				group.addNode(node);
			}
			return new ArrayList<>(binnedColorMap.values());
		}

		private int computeShift(int bins) {
			switch (bins) {
				case 8:
					return 7;
				case 64:
					return 6;
				case 512:
					return 5;
				default:
					return 7;
			}
		}

		private Color binColor(ColorNode node, int shift) {
			Color color = node.getColor();
			int redValue = (color.getRed() >> shift) << shift;
			int greenValue = (color.getGreen() >> shift) << shift;
			int blueValue = (color.getBlue() >> shift) << shift;
			return new Color(redValue, greenValue, blueValue);
		}

		@Override
		public String getName() {
			return "Colors";
		}

		@Override
		public String getDisplayText() {
			return "Colors (" + uniqueColors + " unique colors)";
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

}
