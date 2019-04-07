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
package ghidra.app.util.html;

import java.awt.Color;

/**
 * A loose concept that represents a line of text, potentially with multiple parts, that can
 * be validated against other instances and can change the color of the text.
 * <p>
 * Validation is performed against another {@link ValidatableLine}, which will be set by 
 * calling {@link #setValidationLine(ValidatableLine)}.
 */
public interface ValidatableLine {

	public static final Color INVALID_COLOR = Color.RED;

	public void updateColor(ValidatableLine otherLine, Color invalidColor);

	public boolean isDiffColored();

	public boolean matches(ValidatableLine otherLine);

	public ValidatableLine copy();

	public String getText();

	/**
	 * Sets the other line that this line is validated against.  The other line may be a full, 
	 * partial, or no match at all.
	 * 
	 * @param line the line against which this line is validated
	 */
	public void setValidationLine(ValidatableLine line);

	/**
	 * True means that this line has been matched against another line, <b>regardless of whether 
	 * the two lines are the same or not</b>.
	 * 
	 * @return true if this line has been matched against another line
	 */
	public boolean isValidated();
}
