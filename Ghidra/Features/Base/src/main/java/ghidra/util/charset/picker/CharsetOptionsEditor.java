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
package ghidra.util.charset.picker;

import java.awt.Component;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.beans.PropertyEditorSupport;
import java.nio.charset.Charset;
import java.util.Objects;

/**
 * PropertyEditor for charset options.  This shows a text field and a browse button to bring
 * up a Charset Picker dialog.  The option value is plain text, not a Charset instance.
 */
public class CharsetOptionsEditor extends PropertyEditorSupport {

	private String currentValue;
	private ItemListener itemListener = this::selectedItemChanged;

	@Override
	public String getAsText() {
		return Objects.requireNonNullElse(currentValue, "");
	}

	@Override
	public Object getValue() {
		return getAsText();
	}

	@Override
	public void setAsText(String text) throws IllegalArgumentException {
		currentValue = text;
	}

	@Override
	public void setValue(Object value) {
		if (value == null) {
			currentValue = null;
		}
		else if (value instanceof Charset cs) {
			currentValue = cs.name();
		}
		else if (value instanceof String csName) {
			currentValue = csName;
		}
	}

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public Component getCustomEditor() {
		CharsetPickerField editorComp = new CharsetPickerField();
		editorComp.setCharsetName(currentValue);
		editorComp.addItemListener(itemListener);

		return editorComp;
	}

	private void selectedItemChanged(ItemEvent e) {
		if (e.getSource() instanceof CharsetPickerField cspf) {
			currentValue = cspf.getCharsetName();
			firePropertyChange();
		}
	}
}
