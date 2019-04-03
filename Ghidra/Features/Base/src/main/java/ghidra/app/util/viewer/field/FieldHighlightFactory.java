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
package ghidra.app.util.viewer.field;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.Highlight;
import docking.widgets.fieldpanel.support.HighlightFactory;
import ghidra.app.util.HighlightProvider;

/**
 * Wrapper class to hold field factory information in the text field to be provided to the
 * highlightProvider to get highlights just before the field is painted.
 *
 */
public class FieldHighlightFactory implements HighlightFactory {

	private HighlightProvider provider;
	private Class<? extends FieldFactory> fieldFactoryClass;
	private Object obj;

	/**
	 * Constructs a new FieldHighlightFactory.
	 * @param provider the HighlightProvider that will actually compute the highlights.
	 * @param fieldFactoryClass the class of the field factory that generated the field to be rendered.
	 * @param obj the object that holds the information that will be rendered (usually a code unit)
	 */
	public FieldHighlightFactory(HighlightProvider provider,
			Class<? extends FieldFactory> fieldFactoryClass, Object obj) {
		this.provider = provider;
		this.fieldFactoryClass = fieldFactoryClass;
		this.obj = obj;
	}

	@Override
	public Highlight[] getHighlights(Field field, String text, int cursorTextOffset) {
		return provider.getHighlights(text, obj, fieldFactoryClass, cursorTextOffset);
	}
}
