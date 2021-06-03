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
package docking.widgets;

import java.awt.*;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.border.Border;

import docking.widgets.label.GDHtmlLabel;

/**
 * A common base class for list and table renderer objects, unifying the Ghidra look and feel.
 * <p>
 * It allows (but default-disables) HTML content, automatically paints alternating row
 * background colors, and highlights the drop target in a drag-n-drop operation.
 *
 */
public abstract class AbstractGCellRenderer extends GDHtmlLabel {

	private static final Color ALTERNATE_BACKGROUND_COLOR = new Color(237, 243, 254);

	/** Allows the user to disable alternating row colors on JLists and JTables */
	private static final String DISABLE_ALTERNATING_ROW_COLORS_PROPERTY =
		"disable.alternating.row.colors";

	protected static boolean systemAlternateRowColors = getAlternateRowColors();

	private static boolean getAlternateRowColors() {
		return !Boolean.getBoolean(DISABLE_ALTERNATING_ROW_COLORS_PROPERTY);
	}

	protected final Border focusBorder;
	protected final Border noFocusBorder;
	protected Font defaultFont;
	protected Font fixedWidthFont;
	protected Font boldFont;
	protected int dropRow = -1;

	private boolean instanceAlternateRowColors = true;

	public AbstractGCellRenderer() {
		noFocusBorder = BorderFactory.createEmptyBorder(0, 5, 0, 5);
		Border innerBorder = BorderFactory.createEmptyBorder(0, 4, 0, 4);
		Border outerBorder = BorderFactory.createLineBorder(Color.YELLOW, 1);
		focusBorder = BorderFactory.createCompoundBorder(outerBorder, innerBorder);
		setBorder(noFocusBorder);

		// disable HTML rendering
		setHTMLRenderingEnabled(false);

		setShouldAlternateRowBackgroundColors(true);

		setOpaque(true); // mimic the default table & list cell renderer
	}

	public void setShouldAlternateRowBackgroundColors(boolean alternate) {
		this.instanceAlternateRowColors = alternate;
	}

	/**
	 * Return whether or not the renderer should alternate row background colors.
	 * <p>
	 * A renderer is unable to override an enforcing DISABLE_ALTERNATING_ROW_COLORS_PROPERTY
	 * system property -- if the property has disabled alternating colors (i.e., set to
	 * 'true'), this method returns false. If the property is false, individual renderers
	 * may assert control over alternating row colors.
	 *
	 * @return True if the rows may be painted in alternate background colors, false otherwise
	 * @see #DISABLE_ALTERNATING_ROW_COLORS_PROPERTY
	 */
	public boolean shouldAlternateRowBackgroundColor() {
		if (systemAlternateRowColors) {
			return instanceAlternateRowColors;
		}
		return false;
	}

	/**
	 * Returns the background color appropriate for the given component.  This may vary depending
	 * upon the current OS.
	 *
	 * @param parent The parent being rendered -- likely a list or table.
	 * @param row The row being rendered.
	 * @return the color
	 */
	protected Color getOSDependentBackgroundColor(JComponent parent, int row) {

		if (!shouldAlternateRowBackgroundColor()) {
			return getDefaultBackgroundColor();
		}

// For now we always alternate row colors--it actually makes the various LaFs look nicer
// Leaving the above call in the code so that it can be later found by reference
//		if (!DockingWindowsLookAndFeelUtils.isUsingAquaUI(parent.getUI())) {
//			return parent.getBackground();
//		}

		return getBackgroundColorForRow(row);
	}

	@Override
	public void setFont(Font f) {
		super.setFont(f);
		defaultFont = f;
		fixedWidthFont = new Font("monospaced", defaultFont.getStyle(), defaultFont.getSize());
		boldFont = new Font(defaultFont.getName(), Font.BOLD, defaultFont.getSize());
	}

	protected void superSetFont(Font font) {
		super.setFont(font);
	}

	// sets the font of this renderer to be bold until the next time that
	// getTableCellRenderer() is called, as it resets the font to the default font on each pass
	protected void setBold() {
		super.setFont(boldFont);
	}

	/**
	 * Sets the row where DnD would perform drop operation.
	 * @param dropRow the drop row
	 */
	public void setDropRow(int dropRow) {
		this.dropRow = dropRow;
	}

	protected Border getNoFocusBorder() {
		return noFocusBorder;
	}

	protected Font getDefaultFont() {
		return defaultFont;
	}

	protected Font getFixedWidthFont() {
		return fixedWidthFont;
	}

	protected Font getBoldFont() {
		return boldFont;
	}

	protected Color getDefaultBackgroundColor() {
		return Color.WHITE;
	}

	protected Color getBackgroundColorForRow(int row) {

		if ((row & 1) == 1) {
			return getDefaultBackgroundColor();
		}
		return ALTERNATE_BACKGROUND_COLOR;
	}

// ==================================================================================================
// Methods overridden for performance reasons (see DefaultTableCellRenderer &
//    DefaultListCellRenderer)
//==================================================================================================

	/**
	 * Overridden for performance reasons.
	 * See the <a href="#override">Implementation Note</a>
	 * for more information.
	 *
	 * @since 1.5
	 */
	@Override
	public void invalidate() {
		// stub
	}

	protected void superValidate() {
		super.invalidate();
	}

	/**
	 * Overridden for performance reasons.
	 * See the <a href="#override">Implementation Note</a>
	 * for more information.
	 */
	@Override
	public void validate() {
		// stub
	}

	/**
	 * Overridden for performance reasons.
	 * See the <a href="#override">Implementation Note</a>
	 * for more information.
	 */
	@Override
	public void revalidate() {
		// stub
	}

	/**
	 * Overridden for performance reasons.
	 * See the <a href="#override">Implementation Note</a>
	 * for more information.
	 */
	@Override
	public void repaint(long tm, int x, int y, int width, int height) {
		// stub
	}

	/**
	 * Overridden for performance reasons.
	 * See the <a href="#override">Implementation Note</a>
	 * for more information.
	 */
	@Override
	public void repaint(Rectangle r) {
		// stub
	}

	/**
	 * Overridden for performance reasons.
	 * See the <a href="#override">Implementation Note</a>
	 * for more information.
	 *
	 * @since 1.5
	 */
	@Override
	public void repaint() {
		// stub
	}

	/**
	 * Overridden for performance reasons.
	 * See the <a href="#override">Implementation Note</a>
	 * for more information.
	 */
	@Override
	protected void firePropertyChange(String propertyName, Object oldValue, Object newValue) {
		if (propertyName.equals("text") || propertyName.equals("labelFor") ||
			propertyName.equals("displayedMnemonic") ||
			((propertyName.equals("font") || propertyName.equals("foreground")) &&
				oldValue != newValue &&
				getClientProperty(javax.swing.plaf.basic.BasicHTML.propertyKey) != null)) {

			super.firePropertyChange(propertyName, oldValue, newValue);
		}
	}

	/**
	 * Overridden for performance reasons.
	 * See the <a href="#override">Implementation Note</a>
	 * for more information.
	 */
	@Override
	public void firePropertyChange(String propertyName, boolean oldValue, boolean newValue) {
		// stub
	}
}
