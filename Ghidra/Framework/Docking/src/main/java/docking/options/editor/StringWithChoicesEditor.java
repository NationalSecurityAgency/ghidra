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
package docking.options.editor;

import java.beans.PropertyEditorSupport;
import java.util.List;

public class StringWithChoicesEditor extends PropertyEditorSupport {
	private String[] choices;
	private String value;

	public StringWithChoicesEditor(String[] choices) {
		this.choices = choices;
	}

	public StringWithChoicesEditor(List<String> choices) {
		this.choices = choices.toArray(new String[choices.size()]);
	}

	@Override
	public void setValue(Object o) {
		this.value = (String) o;
		firePropertyChange();
	}

	@Override
	public Object getValue() {
		return value;
	}

	@Override
	public String[] getTags() {
		return choices;
	}

	@Override
	public String getAsText() {
		return value;
	}

	@Override
	public void setAsText(String s) {
		value = s;
		firePropertyChange();
	}

	public void setChoices(String[] choices) {
		this.choices = choices;
	}
}
