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
package ghidra.util.table.field;

import java.awt.Component;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsDefinition;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionNameFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

/**
 * This table field displays the Function Signature for either the program location or the address
 * associated with a row in the table.
 */
public class FunctionSignatureTableColumn
		extends ProgramLocationTableColumnExtensionPoint<Function, Function> {

	private static final FunctionInlineSettingsDefinition INLINE =
		FunctionInlineSettingsDefinition.DEF;
	private static final FunctionThunkSettingsDefinition THUNK =
		FunctionThunkSettingsDefinition.DEF;
	private static final FunctionNoReturnSettingsDefinition NORETURN =
		FunctionNoReturnSettingsDefinition.DEF;
	private static SettingsDefinition[] SETTINGS_DEFS = { INLINE, THUNK, NORETURN };

	private SignatureRenderer renderer = new SignatureRenderer();

	@Override
	public String getColumnDisplayName(Settings settings) {
		return getColumnName();
	}

	@Override
	public String getColumnName() {
		return "Function Signature";
	}

	@Override
	public Function getValue(Function rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		if (rowObject == null) {
			return null;
		}

		return rowObject;
	}

	@Override
	public ProgramLocation getProgramLocation(Function rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {
		if (rowObject == null) {
			return null;
		}
		return new FunctionNameFieldLocation(program, rowObject.getEntryPoint(), 0,
			rowObject.getPrototypeString(false, false), rowObject.getName());
	}

	@Override
	public SettingsDefinition[] getSettingsDefinitions() {
		return SETTINGS_DEFS;
	}

	@Override
	public GColumnRenderer<Function> getColumnRenderer() {
		return renderer;
	}

	@Override
	public int getColumnPreferredWidth() {
		// a reasonable default based upon other standard columns, like label and address columns
		return 200;
	}

	private class SignatureRenderer extends AbstractGhidraColumnRenderer<Function> {

		private void inline(Function function, Settings settings, StringBuilder buffy) {
			if (!function.isInline()) {
				return;
			}

			boolean showInline = INLINE.getValue(settings);
			if (!showInline) {
				return;
			}

			buffy.append("inline ");
		}

		private void noreturn(Function function, Settings settings, StringBuilder buffy) {
			if (!function.hasNoReturn()) {
				return;
			}

			boolean showNoreturn = NORETURN.getValue(settings);
			if (!showNoreturn) {
				return;
			}

			buffy.append("noreturn ");
		}

		private void thunk(Function function, Settings settings, StringBuilder buffy) {
			if (!function.isThunk()) {
				return;
			}

			boolean showThunk = THUNK.getValue(settings);
			if (!showThunk) {
				return;
			}

			buffy.append("thunk ");
		}

		String getSignature(Function function, Settings settings) {

			if (function == null) {
				return null;
			}

			StringBuilder buffy = new StringBuilder();

			inline(function, settings, buffy);
			thunk(function, settings, buffy);
			noreturn(function, settings, buffy);

			String prototypeString = function.getPrototypeString(false, false);
			buffy.append(prototypeString);
			return buffy.toString();
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel label = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();
			Settings settings = data.getColumnSettings();

			label.setFont(getFixedWidthFont());

			Function function = (Function) value;

			label.setText(getSignature(function, settings));

			return label;
		}

		@Override
		public String getFilterString(Function t, Settings settings) {
			return getSignature(t, settings);
		}
	}

}
