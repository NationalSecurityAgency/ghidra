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
package docking.widgets.fieldpanel.internal;

import java.awt.Color;

/**
 * Miscellaneous information needed by fields to paint.
 */
public class PaintContext {

	private Color defaultBackground;
	private Color background;
	private Color foreground;
	private Color selectionColor;
	private Color highlightColor;
	private Color selectedHighlightColor;
	private Color printColor;

	private Color cursorColor;
	private Color focusedCursorColor;
	private Color notFocusedCursorColor;
	private Color invisibleCursorColor;

	private boolean printing = false;
	private boolean textCopying = false;

	/**
	 * Create a new PaintContext with default color values.
	 */
	public PaintContext() {
		defaultBackground = Color.white;
		background = Color.white;
		foreground = Color.black;
		selectionColor = new Color(180, 255, 180);
		highlightColor = new Color(255, 255, 150);
		selectedHighlightColor = Color.green;
		focusedCursorColor = Color.RED;
		cursorColor = focusedCursorColor;
		invisibleCursorColor = new Color(255, 0, 0, 1);
		notFocusedCursorColor = Color.PINK;
	}

	public PaintContext(PaintContext other) {
		defaultBackground = other.defaultBackground;
		background = other.background;
		foreground = other.foreground;
		selectionColor = other.selectionColor;
		highlightColor = other.highlightColor;
		selectedHighlightColor = other.selectedHighlightColor;
		cursorColor = other.cursorColor;
		focusedCursorColor = other.focusedCursorColor;
		notFocusedCursorColor = other.notFocusedCursorColor;
		invisibleCursorColor = other.invisibleCursorColor;
		printColor = other.printColor;
	}

	/**
	 * Returns the current default background color setting that is used when 
	 * there is no special background color or highlight or selection.
	 */
	public final Color getDefaultBackground() {
		return defaultBackground;
	}

	/**
	 * Returns the current background color setting.
	 */
	public final Color getBackground() {
		return background;
	}

	/**
	 * Returns the current foreground color setting.
	 */
	public final Color getForeground() {
		return foreground;
	}

	/**
	 * Returns the current selection color setting.
	 */
	public final Color getSelectionColor() {
		return selectionColor;
	}

	/**
	 * Returns the current selection color setting.
	 */
	public final Color getHighlightColor() {
		return highlightColor;
	}

	/**
	 * Returns the current selection color setting.
	 */
	public final Color getSelectedHighlightColor() {
		return selectedHighlightColor;
	}

	/**
	 * Returns the current cursor color setting.
	 */
	public final Color getCursorColor() {
		return cursorColor;
	}

	public final Color getFocusedCursorColor() {
		return focusedCursorColor;
	}

	public void setSelectionColor(Color c) {
		selectionColor = c;
		adjustSelectedHighlightColor();
	}

	public void setHighlightColor(Color c) {
		highlightColor = c;
		adjustSelectedHighlightColor();
	}

	public void setDefaultBackgroundColor(Color c) {
		defaultBackground = c;
	}

	/**
	 * Returns true if the current background color matches the default background color.
	 */
	public final boolean isDefaultBackground() {
		return defaultBackground.equals(background);
	}

	private void adjustSelectedHighlightColor() {
		int red = (selectionColor.getRed() + highlightColor.getRed()) / 2;
		int green = (selectionColor.getGreen() + highlightColor.getGreen()) / 2;
		int blue = (selectionColor.getBlue() + highlightColor.getBlue()) / 2;
		selectedHighlightColor = new Color(red, green, blue);
	}

	public void setBackgroundColor(Color c) {
		background = c;
	}

	public void setForegroundColor(Color c) {
		foreground = c;
	}

	public void setCursorColor(Color c) {
		cursorColor = c;
		invisibleCursorColor = new Color(c.getRed(), c.getGreen(), c.getBlue(), 1);
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

	public void setPrintColor(Color c) {
		printColor = c;
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
