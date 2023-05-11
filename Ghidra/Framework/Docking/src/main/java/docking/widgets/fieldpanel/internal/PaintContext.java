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
package docking.widgets.fieldpanel.internal;

import java.awt.Color;

import generic.theme.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.util.ColorUtils;

/**
 * Miscellaneous information needed by fields to paint.
 */
public class PaintContext {

	private Color background;
	private Color foreground;
	private Color selectionColor;
	private Color highlightColor;
	private Color selectedHighlightColor;

	private Color cursorColor;
	private Color focusedCursorColor;
	private Color notFocusedCursorColor;
	private Color invisibleCursorColor;

	private boolean printing = false;
	private boolean textCopying = false;
	private ThemeListener themeListener = this::themeChanged;

	/**
	 * Create a new PaintContext with default color values.
	 */
	public PaintContext() {
		background = new GColor("color.bg.fieldpanel");
		foreground = new GColor("color.fg.fieldpanel");
		selectionColor = new GColor("color.bg.fieldpanel.selection");
		highlightColor = new GColor("color.bg.fieldpanel.highlight");
		updateSelectedHighlightColor();
		focusedCursorColor = new GColor("color.cursor.focused");
		notFocusedCursorColor = new GColor("color.cursor.unfocused");
		cursorColor = focusedCursorColor;
		invisibleCursorColor = Palette.NO_COLOR;
		Gui.addThemeListener(themeListener);
	}

	private void themeChanged(ThemeEvent ev) {
		updateSelectedHighlightColor();
	}

	/**
	 * Returns the current background color setting.
	 * @return the current background color setting.
	 */
	public final Color getBackground() {
		return background;
	}

	/**
	 * Returns the current foreground color setting.
	 * @return the current foreground color setting.
	 */
	public final Color getForeground() {
		return foreground;
	}

	/**
	 * Returns the current selection color setting.
	 * @return the current selection color setting.
	 */
	public final Color getSelectionColor() {
		return selectionColor;
	}

	/**
	 * Returns the current highlight color setting.
	 * @return the current highlight color setting.
	 */
	public final Color getHighlightColor() {
		return highlightColor;
	}

	/**
	 * Returns the current selected highlight color setting.
	 * @return the current selected highlight color setting.
	 */
	public final Color getSelectedHighlightColor() {
		return selectedHighlightColor;
	}

	/**
	 * Returns the current cursor color.
	 * @return the current cursor color.
	 */
	public final Color getCursorColor() {
		return cursorColor;
	}

	public final Color getFocusedCursorColor() {
		return focusedCursorColor;
	}

	public void setSelectionColor(Color c) {
		selectionColor = c;
		updateSelectedHighlightColor();
	}

	public void setHighlightColor(Color c) {
		highlightColor = c;
		updateSelectedHighlightColor();
	}

	private void updateSelectedHighlightColor() {
		selectedHighlightColor = ColorUtils.addColors(highlightColor, selectionColor);
	}

	public void setBackgroundColor(Color c) {
		background = c;
	}

	public void setForegroundColor(Color c) {
		foreground = c;
	}

	public void setCursorColor(Color c) {
		cursorColor = c;
		invisibleCursorColor = Palette.NO_COLOR;
	}

	public boolean cursorHidden() {
		return cursorColor == invisibleCursorColor;
	}

	public boolean cursorFocused() {
		return cursorColor == focusedCursorColor;
	}

	public void setCursorFocused(boolean isFocused) {
		cursorColor = isFocused ? focusedCursorColor : notFocusedCursorColor;
	}

	public void setCursorHidden(boolean isHidden) {
		cursorColor = isHidden ? invisibleCursorColor : focusedCursorColor;
	}

	public void setFocusedCursorColor(Color color) {
		focusedCursorColor = color;
	}

	public void setNotFocusedCursorColor(Color color) {
		notFocusedCursorColor = color;
	}

	public Color getNotFocusedCursorColor() {
		return notFocusedCursorColor;
	}

	public void setPrinting(boolean b) {
		printing = b;
	}

	public void setTextCopying(boolean b) {
		textCopying = b;
	}

	public boolean isPrinting() {
		return printing;
	}

	public boolean isTextCopying() {
		return textCopying;
	}
}
