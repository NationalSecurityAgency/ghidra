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
package ghidra.app.util;

import ghidra.app.util.viewer.field.FieldFactory;
import docking.widgets.fieldpanel.support.Highlight;

/**
 * Provider of Highlight objects appropriate for the text, object, and FieldFactory class.
 *
 */
public interface HighlightProvider {

	public static final Highlight[] EMPTY_HIGHLIGHT = new Highlight[0];

	/**
	 * Get the highlights appropriate for the given text, object, and FieldFactory class.
	 * @param text the entire text contained in the field, regardless of layout.
	 * @param obj object that provides the information to be rendered (usually a code unit)
	 * @param fieldFactoryClass the class that indicates what type of field is being rendered.
	 * For Example, address fields would have the AddressFieldFactory class.
	 * @param cursorTextOffset the cursor position within the given text or -1 if no cursor in this field.
	 * @return an array of highlight objects that indicate the location within the text string to
	 * be highlighted.
	 */
	public Highlight[] getHighlights(String text, Object obj,
			Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset);

}
