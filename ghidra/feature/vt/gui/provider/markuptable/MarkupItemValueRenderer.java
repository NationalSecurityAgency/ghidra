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
package ghidra.feature.vt.gui.provider.markuptable;

import java.awt.Color;
import java.awt.Component;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.stringable.*;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.util.exception.AssertException;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;

public class MarkupItemValueRenderer extends AbstractGhidraColumnRenderer<Stringable> {

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		super.getTableCellRendererComponent(data);

		Object value = data.getValue();
		boolean isSelected = data.isSelected();

		if (!(value instanceof Stringable) && value != null) {
			throw new AssertException("Incorrect column value for the markup item value column: " +
				value.getClass().getSimpleName());
		}

		String text = asString((Stringable) value);
		configureRendererForStringable((Stringable) value, text, isSelected);

		return this;
	}

	private String asString(Stringable stringable) {

		if (stringable == null) {
			return "";
		}

		String text = stringable.getDisplayString();
		if (StringUtils.isBlank(text)) {
			return ""; // don't add any special decoration
		}

		return text;
	}

	private void configureRendererForStringable(Stringable stringable, String text,
			boolean isSelected) {

		if (stringable == null) {
			setText(text);
			return;
		}

		if (StringUtils.isBlank(text)) {
			setText(text);
			return; // don't add any special decoration
		}

		setText(text);

		boolean isSymbol = false;
		if (stringable instanceof SymbolStringable) {
			isSymbol = true;
		}
		else if (stringable instanceof FunctionNameStringable) {
			isSymbol = true;
		}
		else if (stringable instanceof MultipleSymbolStringable) {
			isSymbol = true;
		}

		if (!isSymbol) {
			return;
		}

		setBold();
		if (!isSelected) {
			setForeground(Color.BLACK);
		}

		return;
	}

	@Override
	public String getFilterString(Stringable t, Settings settings) {
		return asString(t);
	}
}
