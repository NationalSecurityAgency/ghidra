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
 * Used by {@link Field}s to combine text, attributes and location information (for example to and 
 * from screen and data locations).  FieldFactory classes can use the various implementations
 * of this interface, or create new ones, to include additional information specific to the fields
 * that they create.
 */
public interface FieldElement {

	/**
	 * Returns the text contained by this field element.
	 * @return the text contained by this field element.
	 */
	public String getText();

	/**
	 * Returns the length of the text within this element.  This is a convenience method for 
	 * calling <code>getText().length()</code>.
	 * @return the length of the text within this element.
	 */
	public int length();

	/**
	 * Returns the string width of this element.  The width is based upon the associated 
	 * FontMetrics object within this element.
	 * @return the string width of this element.
	 */
	public int getStringWidth();

	/**
	 * Returns the amount of height above the baseline of this element.
	 * @return the amount of height above the baseline of this element.
	 */
	public int getHeightAbove();

	/**
	 * Returns the amount of height below the baseline of this element.
	 * @return the amount of height below the baseline of this element.
	 */
	public int getHeightBelow();

	/**
	 * Returns the character at the given index.
	 * @param index the index of the character in this field element.
	 * @return the character at the given index.
	 */
	public char charAt(int index);

	/**
	 * Returns the color for a given character within this element, since different colors may be
	 * applied to different characters.
	 * 
	 * @param charIndex The character index
	 * @return the color for a given character within this element.
	 */
	public Color getColor(int charIndex);

	/**
	 * Returns a new FieldElement containing just the characters beginning at the given index.
	 * 
	 * @param start The starting index (inclusive) from which to substring this element.
	 * @return a new FieldElement containing just the characters beginning at the given index.
	 */
	public FieldElement substring(int start);

	/**
	 * Returns a new FieldElement containing just the characters beginning at the given start 
	 * index (inclusive) and ending at the given end index (exclusive).
	 * 
	 * @param start The starting index (inclusive) from which to substring this element.
	 * @param end The end index (exclusive) to which the substring will be performed.
	 * @return a new FieldElement containing just the characters beginning at the given index.
	 */
	public FieldElement substring(int start, int end);

	/**
	 * Returns a new FieldElement with all occurrences of the target characters replaced with the 
	 * given replacement character.
	 * @param targets The array of characters to replace.
	 * @param replacement The replacement character.
	 * @return a new FieldElement with all occurrences of the target characters replaced with the 
	 * given replacement character.
	 */
	public FieldElement replaceAll(char[] targets, char replacement);

	/**
	 * As the name implies, this method returns the maximum number of characters from this field
	 * element that will fit within the given width.
	 * 
	 * @param width The width constraint
	 * @return the maximum number of characters from this field element that will fit within 
	 * the given width.
	 */
	public int getMaxCharactersForWidth(int width);

	/**
	 * Translates the given character index to a data location related to the data model, as 
	 * determined by the FieldFactory.
	 * 
	 * @param characterIndex The character index to translate.
	 * @return The data location in the model coordinates.
	 */
	public RowColLocation getDataLocationForCharacterIndex(int characterIndex);

	/**
	 * Returns the character index appropriate for the given data location
	 * @param dataRow the row in the data model as determined by the creating field factory.
	 * @param dataColumn the column in the data model as determined by the creating field factory.
	 * @return the character index appropriate for the given data location
	 */
	public int getCharacterIndexForDataLocation(int dataRow, int dataColumn);

	/**
	 * Paints the text contained in this field element at the given x,y screen coordinate using the
	 * given Graphics object.
	 * @param g the Graphics object used to paint the field text.
	 * @param x the horizontal screen position to paint
	 * @param y the vertical screen position to paint.
	 */
	public void paint(JComponent c, Graphics g, int x, int y);

	/**
	 * Returns the inner-most FieldElement inside this field element at the given location
	 * @param column the charactor offset. 
	 * @return  the inner-most FieldElement inside this field element at the given location
	 */
	public FieldElement getFieldElement(int column);

}
