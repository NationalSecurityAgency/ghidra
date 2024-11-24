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
package docking.options.editor;

import java.beans.PropertyEditorSupport;

public class StringEditor extends PropertyEditorSupport {

	public StringEditor() {
		super();
	}

	/**
	 * The comment in the parent "PropertyEditorSupport" reads:
	 * 
	 * <blockquote>
	 * <p>
	 * Sets the property value by parsing a given String. May raise
	 * java.lang.IllegalArgumentException if either the String is badly formatted or if this kind of
	 * property can't be expressed as text.
	 * </p>
	 * </blockquote>
	 * 
	 * <p>
	 * which would be fine, except for the fact that Java initializes "value" to null, so every use
	 * of this method has to insure that setValue has been called at least once with a non-null
	 * value. If not, the method throws the IllegalArgumentException despite the fact that the input
	 * is not badly formatted and CAN be expressed as text.
	 */
	@Override
	public void setAsText(String text) throws java.lang.IllegalArgumentException {
		Object value = getValue();
		if (value == null || value instanceof String) {
			setValue(text);
			return;
		}
		throw new java.lang.IllegalArgumentException(text);
	}
}
