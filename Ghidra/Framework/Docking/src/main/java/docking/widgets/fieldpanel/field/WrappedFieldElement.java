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
 * A simple field element that wraps another field element. This class allows clients to wrap field
 * elements without having to re-implement all of the methods themselves. 
 */
public abstract class WrappedFieldElement implements FieldElement {

	private FieldElement delegate;

	public WrappedFieldElement(FieldElement delegate) {
		this.delegate = delegate;
	}

	@Override
	public String getText() {
		return delegate.getText();
	}

	@Override
	public int length() {
		return delegate.length();
	}

	@Override
	public int getStringWidth() {
		return delegate.getStringWidth();
	}

	@Override
	public int getHeightAbove() {
		return delegate.getHeightAbove();
	}

	@Override
	public int getHeightBelow() {
		return delegate.getHeightBelow();
	}

	@Override
	public char charAt(int index) {
		return delegate.charAt(index);
	}

	@Override
	public Color getColor(int charIndex) {
		return delegate.getColor(charIndex);
	}

	@Override
	public FieldElement substring(int start) {
		return delegate.substring(start);
	}

	@Override
	public FieldElement substring(int start, int end) {
		return delegate.substring(start, end);
	}

	@Override
	public FieldElement replaceAll(char[] targets, char replacement) {
		return delegate.replaceAll(targets, replacement);
	}

	@Override
	public int getMaxCharactersForWidth(int width) {
		return delegate.getMaxCharactersForWidth(width);
	}

	@Override
	public RowColLocation getDataLocationForCharacterIndex(int characterIndex) {
		return delegate.getDataLocationForCharacterIndex(characterIndex);
	}

	@Override
	public int getCharacterIndexForDataLocation(int dataRow, int dataColumn) {
		return delegate.getCharacterIndexForDataLocation(dataRow, dataColumn);
	}

	@Override
	public void paint(JComponent c, Graphics g, int x, int y) {
		delegate.paint(c, g, x, y);
	}

	@Override
	public FieldElement getFieldElement(int column) {
		return delegate.getFieldElement(column);
	}

	@Override
	public String toString() {
		return delegate.toString();
	}
}
