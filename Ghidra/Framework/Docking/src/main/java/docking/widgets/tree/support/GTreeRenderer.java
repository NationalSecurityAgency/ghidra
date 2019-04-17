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
package docking.widgets.tree.support;

import java.awt.*;

import javax.swing.Icon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

public class GTreeRenderer extends DefaultTreeCellRenderer {
	private static final long serialVersionUID = 1L;
	private static final Color VALID_DROP_TARGET_COLOR = new Color( 200, 200, 255 );
	private static final int DEFAULT_MIN_ICON_WIDTH = 22;
	
	private Object dropTarget;
	private boolean paintDropTarget;
	
	private Font cachedDefaultFont;
	private Font cachedBoldFont;
	private int minIconWidth = DEFAULT_MIN_ICON_WIDTH;
	
	/**
	 * 
	 * @see javax.swing.tree.DefaultTreeCellRenderer#getTreeCellRendererComponent(javax.swing.JTree, java.lang.Object, boolean, boolean, boolean, int, boolean)
	 */
	@Override
	public Component getTreeCellRendererComponent(JTree tree, Object value, 
			boolean selected1, boolean expanded, boolean leaf, int row, boolean hasFocus1) {

		super.getTreeCellRendererComponent(tree, value, selected1, expanded, leaf, row, hasFocus1); 
		GTreeNode node = (GTreeNode)value;

		String text = node.getName();
		setText(text);
		setToolTipText(node.getToolTip());

		Icon icon = node.getIcon(expanded);
		if ( icon == null ) {
			icon = getIcon();
		}
		else {
			setIcon( icon );
		}
		
		updateIconTextGap(icon, minIconWidth);
		
		paintDropTarget = (value==dropTarget);
		
		GTree gtree = node.getTree();
		
		GTreeFilter filter = gtree == null ? null : gtree.getFilter();
		boolean isBold = (filter != null) && filter.showFilterMatches() && filter.acceptsNode(node);
		setFont( getFont( isBold ) );
        return this;
	}

	protected void updateIconTextGap(Icon icon, int minWidth) {
		int iconWidth = 0;
		if (icon != null) {
			iconWidth = icon.getIconWidth();
		}
		setIconTextGap(Math.max(minWidth-iconWidth, 2));
	}

	@Override // overridden to recalculate icon text gaps
	public void setIcon( Icon icon ) {
	    super.setIcon( icon );
	    updateIconTextGap( icon, minIconWidth );
	}
	
	public int getMinIconWidth() {
		return minIconWidth;
	}

	public void setMinIconWidth(int minIconWidth) {
		this.minIconWidth = minIconWidth;
	}

	// allows us to change the font to bold as needed without erasing the original font
	private Font getFont(boolean bold) {
		Font font = getFont();
		// check if someone set a  new font on the renderer
		if ( font != cachedDefaultFont && font != cachedBoldFont ) {
			cachedDefaultFont = font;
			
			// Bug Alert!: 
			// We must create a new font here and not use deriveFont().  Using derive font has
			// bugs when calculating the string width for a bold derived font.
			cachedBoldFont = new Font( font.getFamily(), Font.BOLD, font.getSize() );
		}
		return bold ? cachedBoldFont : cachedDefaultFont;
	}
	
	// our parent makes this call in the paint() method so we cannot just call setBackground() in
	// getTreeCellRendererComponent(), but we must instead make sure that the paint() method gets
	// the correct color
	@Override
	public Color getBackgroundNonSelectionColor() {
		if ( paintDropTarget ) {			
			return VALID_DROP_TARGET_COLOR;
		}
		return super.getBackgroundNonSelectionColor();
	}
	
	public void setRendererDropTarget( Object target ) {
		this.dropTarget = target;
	}
}
