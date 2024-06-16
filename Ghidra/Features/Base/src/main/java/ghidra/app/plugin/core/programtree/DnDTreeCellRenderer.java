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
package ghidra.app.plugin.core.programtree;

import java.awt.*;
import java.util.*;

import javax.swing.Icon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

import docking.widgets.GComponent;
import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.program.model.listing.Group;
import resources.ResourceManager;

/**
 * Cell renderer for the drag and drop tree.
 */
class DnDTreeCellRenderer extends DefaultTreeCellRenderer {
	private static final Color BACKGROUND_UNSELECTED = new GColor("color.bg.tree");
	private static final Color BACKGROUND_SELECTED = new GColor("color.bg.tree.selected");
	private static final Color FOREGROUND_SELECTED = new GColor("color.fg.tree.selected");

	private static final String DISABLED_DOCS = "DisabledDocument.gif";
	private static final String DISABLED_FRAGMENT = "DisabledFragment";
	private static final String DISABLED_VIEWED_FRAGMENT = "DisabledViewedFragment";
	private static final String DISABLED_EMPTY_FRAGMENT = "DisabledEmptyFragment";
	private static final String DISABLED_VIEWED_EMPTY_FRAGMENT = "DisabledViewedEmptyFragment";
	private static final String DISABLED_VIEWED_OPEN_FOLDER = "DisabledViewedOpenFolder";
	private static final String DISABLED_VIEWED_CLOSED_FOLDER = "DisabledViewedClosedFolder";
	private static final String DISABLED_VIEWED_CLOSED_FOLDER_WITH_DESC =
		"DisabledViewedClosedFolderWithDescendants";
	private static final String DISABLED_CLOSED_FOLDER = "DisabledClosedFolder";
	private static final String DISABLED_OPEN_FOLDER = "DisabledOpenedFolder";

	private static final String DOCS = "icon.plugin.programtree.docs";
	static final String FRAGMENT = "icon.plugin.programtree.fragment";
	private static final String EMPTY_FRAGMENT = "icon.plugin.programtree.fragment.empty";

	static final String VIEWED_FRAGMENT = "icon.plugin.programtree.fragment.viewed";
	static final String VIEWED_EMPTY_FRAGMENT = "icon.plugin.programtree.fragment.viewed.empty";
	static final String VIEWED_CLOSED_FOLDER = "icon.plugin.programtree.fragment.closed.folder";
	static final String VIEWED_OPEN_FOLDER = "icon.plugin.programtree.fragment.open.folder";
	static final String VIEWED_CLOSED_FOLDER_WITH_DESC =
		"icon.plugin.programtree.fragment.viewed.closed.folder.with.description";
	static final String CLOSED_FOLDER = "icon.plugin.programtree.closed.folder";
	static final String OPEN_FOLDER = "icon.plugin.programtree.open.folder";

	private Map<String, Icon> iconMap;

	private Color defaultSelectionColor;
	private Color defaultNonSelectionColor;
	private Color selectionForDragColor;
	private Color nonSelectionForDragColor;
	private Color defaultTextSelectionColor;
	private int rowForFeedback;

	/**
	 * Construct a new DnDTreeCellRenderer.
	 */
	DnDTreeCellRenderer() {
		super();
		defaultNonSelectionColor = BACKGROUND_UNSELECTED;
		defaultSelectionColor = BACKGROUND_SELECTED;
		defaultTextSelectionColor = FOREGROUND_SELECTED;
		rowForFeedback = -1;

		// disable HTML rendering
		setHTMLRenderingEnabled(false);

		loadImages();

	}

	/**
	 * Enables and disables the rendering of HTML content in this renderer.  If enabled, this
	 * renderer will interpret HTML content when the text this renderer is showing begins with
	 * <tt>&lt;html&gt;</tt>
	 *
	 * @param enable true to enable HTML rendering; false to disable it
	 */
	public void setHTMLRenderingEnabled(boolean enable) {
		putClientProperty(GComponent.HTML_DISABLE_STRING, !enable);
	}

	void setSelectionForDrag(Color color) {
		selectionForDragColor = color;
	}

	void setNonSelectionForDrag(Color color) {
		nonSelectionForDragColor = color;
	}

	void setRowForFeedback(int row) {
		rowForFeedback = row;
	}

	/**
	 * Configures the renderer based on the passed in components.
	 * The icon is set according to value, expanded, and leaf
	 * parameters.
	 */
	@Override
	public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel,
			boolean expanded, boolean leaf, int row, boolean isFocused) {

		super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, isFocused);
		ProgramNode node = (ProgramNode) value;

		Group group = node.getGroup();
		Icon icon = null;
		boolean isInView = node.isInView();

		if (group == null && !node.isRoot()) {
			// must be a document
			if (node.isDeleted()) {
				icon = iconMap.get(DISABLED_DOCS);
			}
			else {
				icon = iconMap.get(DOCS);
			}
		}
		else if (node.isFragment()) {
			icon = getFragmentIcon(node, isInView);
		}
		else {
			icon = getFolderIcon(expanded, leaf, node, isInView);
		}

		if (icon != null) {
			setIcon(icon);
		}
		setSelectionColors(sel, row, node, (DragNDropTree) tree);
		return this;
	}

	/**
	 * Set colors for background according to the draw feedback state.
	 * @param selected true if selected
	 * @param row row of the node
	 * @param node node to render
	 * @param dtree tree
	 */
	private void setSelectionColors(boolean selected, int row, ProgramNode node,
			DragNDropTree dtree) {
		if (dtree.getDrawFeedbackState()) {
			if (row == rowForFeedback) {
				if (!selected) {
					setBackgroundNonSelectionColor(nonSelectionForDragColor);
				}
				else {
					setBackgroundSelectionColor(selectionForDragColor);
				}
			}
			else {
				setBackgroundSelectionColor(defaultSelectionColor);
				setTextSelectionColor(defaultTextSelectionColor);
				setBackgroundNonSelectionColor(defaultNonSelectionColor);
			}
			setToolTipText(null);
		}
		else {
			setBackgroundSelectionColor(defaultSelectionColor);
			setTextSelectionColor(defaultTextSelectionColor);
			setBackgroundNonSelectionColor(defaultNonSelectionColor);
			setToolTipText(dtree.getToolTipText(node));
		}
	}

	private Icon getFolderIcon(boolean expanded, boolean leaf, ProgramNode node, boolean isInView) {
		Icon icon = null;
		if (leaf && node.isRoot()) {
			if (isInView) {
				icon = iconMap.get(VIEWED_CLOSED_FOLDER);
			}
			else {
				icon = iconMap.get(CLOSED_FOLDER);
			}
		}
		else if (leaf) {
			icon = processLeafNode(node, isInView);
		}

		else if (node.isDeleted()) {
			icon = processDeletedNode(expanded, node, isInView);
		}
		else if (expanded) {
			if (isInView) {
				icon = iconMap.get(VIEWED_OPEN_FOLDER);
			}
			else {
				icon = iconMap.get(OPEN_FOLDER);
			}
		}
		else if (isInView) {
			icon = iconMap.get(VIEWED_CLOSED_FOLDER);
		}
		else if (node.hasDescendantsInView()) {
			icon = iconMap.get(VIEWED_CLOSED_FOLDER_WITH_DESC);
		}
		else {
			icon = iconMap.get(CLOSED_FOLDER);
		}
		return icon;
	}

	private Icon processDeletedNode(boolean expanded, ProgramNode node, boolean isInView) {
		Icon icon = null;
		if (expanded) {
			if (isInView) {
				icon = iconMap.get(DISABLED_VIEWED_OPEN_FOLDER);
			}
			else {
				icon = iconMap.get(DISABLED_OPEN_FOLDER);
			}
		}
		else {
			if (isInView) {
				icon = iconMap.get(DISABLED_VIEWED_CLOSED_FOLDER);
			}
			else {
				if (node.hasDescendantsInView()) {
					icon = iconMap.get(DISABLED_VIEWED_CLOSED_FOLDER_WITH_DESC);
				}
				else {
					icon = iconMap.get(DISABLED_CLOSED_FOLDER);
				}
			}
		}
		return icon;
	}

	private Icon processLeafNode(ProgramNode node, boolean isInView) {
		Icon icon = null;
		// empty module
		if (node.isDeleted()) {
			if (isInView) {
				icon = iconMap.get(DISABLED_VIEWED_CLOSED_FOLDER);
			}
			else {
				icon = iconMap.get(DISABLED_VIEWED_CLOSED_FOLDER);
			}
		}
		else if (isInView) {
			icon = iconMap.get(VIEWED_CLOSED_FOLDER);
		}
		else {
			icon = iconMap.get(CLOSED_FOLDER);
		}
		return icon;
	}

	private Icon getFragmentIcon(ProgramNode node, boolean isInView) {
		Icon icon;
		boolean isEmpty = false;
		try {
			isEmpty = node.getFragment().isEmpty();
		}
		catch (ConcurrentModificationException e) {
			// not sure if this can still happpen
		}
		if (node.isDeleted()) {
			if (isInView) {
				if (isEmpty) {
					icon = iconMap.get(DISABLED_VIEWED_EMPTY_FRAGMENT);
				}
				else {
					icon = iconMap.get(DISABLED_VIEWED_FRAGMENT);
				}
			}
			else {
				// NOT in view
				if (isEmpty) {
					icon = iconMap.get(DISABLED_EMPTY_FRAGMENT);
				}
				else {
					icon = iconMap.get(DISABLED_FRAGMENT);
				}
			}
		}
		else if (node.isInView()) {
			if (isEmpty) {
				icon = iconMap.get(VIEWED_EMPTY_FRAGMENT);
			}
			else {
				icon = iconMap.get(VIEWED_FRAGMENT);
			}
		}
		else {
			if (isEmpty) {
				icon = iconMap.get(EMPTY_FRAGMENT);
			}
			else {
				icon = iconMap.get(FRAGMENT);
			}
		}
		return icon;
	}

	/**
	 * load images for icons.
	 */
	private void loadImages() {
		// try to load icon images
		iconMap = new HashMap<>();
		String[] iconIds = { DOCS, FRAGMENT, EMPTY_FRAGMENT, VIEWED_FRAGMENT, VIEWED_EMPTY_FRAGMENT,
			VIEWED_CLOSED_FOLDER, VIEWED_OPEN_FOLDER, VIEWED_CLOSED_FOLDER_WITH_DESC, CLOSED_FOLDER,
			OPEN_FOLDER, };
		String[] disabledNames = { DISABLED_DOCS, DISABLED_FRAGMENT, DISABLED_EMPTY_FRAGMENT,
			DISABLED_VIEWED_EMPTY_FRAGMENT, DISABLED_VIEWED_FRAGMENT, DISABLED_VIEWED_CLOSED_FOLDER,
			DISABLED_VIEWED_OPEN_FOLDER, DISABLED_VIEWED_CLOSED_FOLDER_WITH_DESC,
			DISABLED_CLOSED_FOLDER, DISABLED_OPEN_FOLDER, };

		for (int i = 0; i < iconIds.length; i++) {
			GIcon icon = new GIcon(iconIds[i]);
			iconMap.put(iconIds[i], icon);
			Icon disabledIcon = ResourceManager.getDisabledIcon(icon);
			iconMap.put(disabledNames[i], disabledIcon);
		}
	}

	@Override
	public Dimension getPreferredSize() {
		Dimension dim = super.getPreferredSize();
		if (dim != null) {
			return new Dimension(dim.width, dim.height + 2);
		}
		return dim;
	}
}
