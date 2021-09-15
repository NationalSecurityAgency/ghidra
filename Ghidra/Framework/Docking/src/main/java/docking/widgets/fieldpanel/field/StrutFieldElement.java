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
package docking.widgets.fieldpanel.field;

import java.awt.Color;
import java.awt.Graphics;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.support.RowColLocation;

/**
 * Used to force a clip to happen by using this field with space characters and size that far
 * exceeds the available painting width.
 */
public class StrutFieldElement implements FieldElement {

	private final int width;

	public StrutFieldElement(int width) {
		this.width = width;
	}

	@Override
	public char charAt(int index) {
		return ' ';
	}

	@Override
	public int getCharacterIndexForDataLocation(int dataRow, int dataColumn) {
		return -1; // we have not characters
	}

	@Override
	public RowColLocation getDataLocationForCharacterIndex(int characterIndex) {
		return new RowColLocation(0, 0);
	}

	@Override
	public Color getColor(int charIndex) {
		return Color.BLACK;
	}

	@Override
	public FieldElement getFieldElement(int characterOffset) {
		return this;
	}

	@Override
	public int getHeightAbove() {
		return 0;
	}

	@Override
	public int getHeightBelow() {
		return 0;
	}

	@Override
	public int getMaxCharactersForWidth(int stringWidth) {
		return 0;
	}

	@Override
	public int getStringWidth() {
		return width;
	}

	@Override
	public String getText() {
		return width == 0 ? "" : " ";
	}

	@Override
	public int length() {
		return width == 0 ? 0 : 1;
	}

	@Override
	public void paint(JComponent c, Graphics g, int x, int y) {
		// nothing to paint
	}

	@Override
	public FieldElement replaceAll(char[] targets, char replacement) {
		return this;
	}

	@Override
	public FieldElement substring(int start) {
		return new StrutFieldElement(0);
	}

	@Override
	public FieldElement substring(int start, int end) {
		return new StrutFieldElement(0);
	}

	@Override
	public String toString() {
		return ""; // empty text placeholder
	}
}
