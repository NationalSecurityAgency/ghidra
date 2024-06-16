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
import javax.swing.plaf.UIResource;
import javax.swing.plaf.basic.BasicHTML;
import javax.swing.table.DefaultTableCellRenderer;

import docking.widgets.label.GDHtmlLabel;
import generic.theme.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import generic.theme.GThemeDefaults.Colors.Tables;
import ghidra.util.Msg;
import util.CollectionUtils;
import utilities.util.reflection.ReflectionUtilities;

/**
 * A common base class for list and table renderer objects, unifying the Ghidra look and feel.
 * <p>
 * It allows (but default-disables) HTML content, automatically paints alternating row background
 * colors, and highlights the drop target in a drag-n-drop operation.
 * <p>
 * The preferred method to change the font used by this renderer is {@link #setBaseFontId(String)}.
 * If you would like this renderer to use a monospaced font, then, as an alternative to creating a
 * font ID, you can instead override {@link #getDefaultFont()} to return this
 * class's {@link #fixedWidthFont}.  Also, the fixed width font of this class is based on the
 * default font set when calling {@link #setBaseFontId(String)}, so it stays up-to-date with theme
 * changes.
 */
public abstract class AbstractGCellRenderer extends GDHtmlLabel {
	private static final Color BACKGROUND_COLOR = new GColor("color.bg.table.row");
	private static final Color ALT_BACKGROUND_COLOR = new GColor("color.bg.table.row.alt");

	private static final String BASE_FONT_ID = "font.table.base";

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
	protected Font italicFont;
	protected int dropRow = -1;

	private boolean instanceAlternateRowColors = true;

	public AbstractGCellRenderer() {

		setBaseFontId(BASE_FONT_ID);

		noFocusBorder = BorderFactory.createEmptyBorder(0, 5, 0, 5);
		Border innerBorder = BorderFactory.createEmptyBorder(0, 4, 0, 4);
		Border outerBorder = BorderFactory.createLineBorder(Palette.YELLOW, 1);
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
	protected Color getAlternatingBackgroundColor(JComponent parent, int row) {

		if (!shouldAlternateRowBackgroundColor()) {
			return getDefaultBackgroundColor();
		}

		return getBackgroundColorForRow(row);
	}

	/**
	 * Sets this renderer's theme font id.  This will be used to load the base font and to create
	 * the derived fonts, such as bold and fixed width.
	 * @param fontId the font id
	 * @see Gui#registerFont(Component, String)
	 */
	public void setBaseFontId(String fontId) {
		Font f = Gui.getFont(fontId);
		defaultFont = f;
		fixedWidthFont = new Font("monospaced", f.getStyle(), f.getSize());
		boldFont = f.deriveFont(Font.BOLD);
		italicFont = f.deriveFont(Font.ITALIC);

		Gui.registerFont(this, fontId);
	}

	@Override
	public void setFont(Font f) {
		super.setFont(f);

		checkForInvalidSetFont(f);
	}

	private void checkForInvalidSetFont(Font f) {
		//
		// Due to the nature of how setFont() is typically used (external client setup vs internal
		// rendering), we created setBaseFontId() to allow external clients to set the base font in
		// a way that is consistent with theming.  Ignore any request to use one of our existing
		// fonts, as some clients may do that from the getTableCellRendererComponent() method.
		//
		if (defaultFont == null ||
			CollectionUtils.isOneOf(f, defaultFont, fixedWidthFont, boldFont, italicFont)) {
			return;
		}

		if (Gui.isUpdatingTheme()) {
			return; // the UI will set fonts while the theme is updating
		}

		String caller = ReflectionUtilities
				.getClassNameOlderThan(AbstractGCellRenderer.class.getName(), "generic.theme");
		Msg.debug(this, "Calling setFont() on the renderer is discouraged.  " +
			"To change the font, call setBaseFontId().  Called from " + caller);
	}

	/**
	 * Sets the font of this renderer to be bold until the next time that getTableCellRenderer() is
	 * called, as it resets the font to the default font on each pass.
	 * @see #getDefaultFont()
	 */
	protected void setBold() {
		super.setFont(boldFont);
	}

	/**
	 * Sets the font of this renderer to be italic until the next time that getTableCellRenderer()
	 * is called, as it resets the font to the default font on each pass.
	 * @see #getDefaultFont()
	 */
	protected void setItalic() {
		super.setFont(italicFont);
	}

	protected Font getDefaultFont() {
		return defaultFont;
	}

	public Font getFixedWidthFont() {
		return fixedWidthFont;
	}

	public Font getBoldFont() {
		return boldFont;
	}

	public Font getItalicFont() {
		return italicFont;
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

	protected Color getDefaultBackgroundColor() {
		return BACKGROUND_COLOR;
	}

	protected Color getBackgroundColorForRow(int row) {

		if ((row & 1) == 1) {
			return getDefaultBackgroundColor();
		}
		return ALT_BACKGROUND_COLOR;
	}

	protected Color getErrorForegroundColor(boolean isSelected) {
		return isSelected ? Tables.ERROR_SELECTED : Tables.ERROR_UNSELECTED;
	}

	protected Color getUneditableForegroundColor(boolean isSelected) {
		return isSelected ? Tables.UNEDITABLE_SELECTED : Tables.UNEDITABLE_UNSELECTED;
	}

//==================================================================================================
// Methods overridden for performance reasons (see DefaultTableCellRenderer &
//    DefaultListCellRenderer)
//==================================================================================================

	/**
	 * See {@link DefaultTableCellRenderer} class header javadoc for more info.
	 */
	@Override
	public void invalidate() {
		// stub
	}

	protected void superValidate() {
		super.invalidate();
	}

	/**
	 * See {@link DefaultTableCellRenderer} class header javadoc for more info.
	 */
	@Override
	public void validate() {
		// stub
	}

	/**
	 * See {@link DefaultTableCellRenderer} class header javadoc for more info.
	 */
	@Override
	public void revalidate() {
		// stub
	}

	/**
	 * See {@link DefaultTableCellRenderer} class header javadoc for more info.
	 */
	@Override
	public void repaint(long tm, int x, int y, int width, int height) {
		// stub
	}

	/**
	 * See {@link DefaultTableCellRenderer} class header javadoc for more info.
	 */
	@Override
	public void repaint(Rectangle r) {
		// stub
	}

	/**
	 * See {@link DefaultTableCellRenderer} class header javadoc for more info.
	 */
	@Override
	public void repaint() {
		// stub
	}

	/**
	 * See {@link DefaultTableCellRenderer} class header javadoc for more info.
	 */
	@Override
	protected void firePropertyChange(String property, Object oldValue, Object newValue) {
		if (property.equals("text") || property.equals("labelFor") ||
			property.equals("displayedMnemonic") || property.equals("html")) {
			super.firePropertyChange(property, oldValue, newValue);
		}
		else if (getClientProperty(BasicHTML.propertyKey) != null) {
			if (property.equals("font") || property.equals("foreground")) {
				super.firePropertyChange(property, oldValue, newValue);
			}
		}
	}

	/**
	 * See {@link DefaultTableCellRenderer} class header javadoc for more info.
	 */
	@Override
	public void firePropertyChange(String propertyName, boolean oldValue, boolean newValue) {
		// stub
	}

	/**
	 * Overrides this method to ensure that the new foreground color is not
	 * a {@link GColorUIResource}. Some Look and Feels will ignore color values that extend
	 * {@link UIResource}, choosing instead their own custom painting behavior. By not using a
	 * UIResource, we prevent the Look and Feel from overriding this renderer's color value.
	 *
	 * @param fg the new foreground color
	 */
	@Override
	public void setForeground(Color fg) {
		super.setForeground(fromUiResource(fg));
	}

	/**
	 * Overrides this method to ensure that the new background color is not
	 * a {@link GColorUIResource}. Some Look and Feels will ignore color values that extend
	 * {@link UIResource}, choosing instead their own custom painting behavior. By not using a
	 * UIResource, we prevent the Look and Feel from overriding this renderer's color value.
	 *
	 * @param bg the new background color
	 */
	@Override
	public void setBackground(Color bg) {
		super.setBackground(fromUiResource(bg));
	}

	/**
	 * Checks and converts any {@link GColorUIResource} to a {@link GColor}
	 * @param color the color to check if it is a {@link UIResource}
	 * @return either the given color or if it is a {@link GColorUIResource}, then a plain
	 * {@link GColor} instance referring to the same theme color  property id.
	 */
	private Color fromUiResource(Color color) {
		if (color instanceof GColorUIResource uiResource) {
			return uiResource.toGColor();
		}
		return color;
	}

}
