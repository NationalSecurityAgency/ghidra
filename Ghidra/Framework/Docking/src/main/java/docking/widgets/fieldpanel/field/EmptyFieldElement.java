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
package docking.widgets.fieldpanel.field;

import java.awt.Color;
import java.awt.Graphics;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.support.RowColLocation;

/**
 * Used to force a clip to happen when the max lines is exceeded in the VerticalLayoutTextField
 */

public class EmptyFieldElement implements FieldElement {

	private final int width;

	public EmptyFieldElement(int width) {
		this.width = width;

	}

	public char charAt(int index) {
		return ' ';
	}

	public int getCharacterIndexForDataLocation(int dataRow, int dataColumn) {
		return 0;
	}

	public Color getColor(int charIndex) {
		return Color.BLACK;
	}

	public RowColLocation getDataLocationForCharacterIndex(int characterIndex) {
		return new RowColLocation(0, 0);
	}

	public FieldElement getFieldElement(int column) {
		return this;
	}

	public int getHeightAbove() {
		return 0;
	}

	public int getHeightBelow() {
		return 0;
	}

	public int getMaxCharactersForWidth(int stringWidth) {
		return 0;
	}

	public int getStringWidth() {
		return width;
	}

	public String getText() {
		return width == 0 ? "" : " ";
	}

	public int length() {
		return width == 0 ? 0 : 1;
	}

	public void paint(JComponent c, Graphics g, int x, int y) {
	}

	public FieldElement replaceAll(char[] targets, char replacement) {
		return this;
	}

	public FieldElement substring(int start) {
		return new EmptyFieldElement(0);
	}

	public FieldElement substring(int start, int end) {
		return new EmptyFieldElement(0);
	}

}
