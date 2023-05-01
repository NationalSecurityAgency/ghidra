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
package ghidra.app.decompiler.component.hover;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.plugin.core.datamgr.util.DataTypeUtils;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.NumericUtilities;

public class DataTypeDecompilerHover extends AbstractConfigurableHover
		implements DecompilerHoverService {

	private static final String NAME = "Data Type Display";
	private static final String DESCRIPTION =
		"Show data type contents when hovering over a type name.";

	// note: this is relative to other DecompilerHovers; a higher priority gets called first
	private static final int PRIORITY = 20;

	protected DataTypeDecompilerHover(PluginTool tool) {
		super(tool, PRIORITY);
	}

	@Override
	protected String getName() {
		return NAME;
	}

	@Override
	protected String getDescription() {
		return DESCRIPTION;
	}

	@Override
	protected String getOptionsCategory() {
		return GhidraOptions.CATEGORY_DECOMPILER_POPUPS;
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		if (!enabled) {
			return null;
		}

		if (!(field instanceof ClangTextField)) {
			return null;
		}

		ClangToken token = ((ClangTextField) field).getToken(fieldLocation);
		DataType dt = DecompilerUtils.getDataType(token);
		if (dt == null) {
			return null;
		}

		String toolTipText = null;
		if (token instanceof ClangFieldToken) {
			toolTipText = createFieldToolTipText((ClangFieldToken) token, dt);
		}
		else {
			toolTipText = ToolTipUtils.getToolTipText(dt);
		}

		return createTooltipComponent(toolTipText);
	}

	private String createFieldToolTipText(ClangFieldToken token, DataType parentType) {
		ClangFieldToken fieldToken = token;
		int offset = fieldToken.getOffset();
		DataType fieldType = getFieldDataType(fieldToken);

		//
		// Parent:     BarBar
		// Offset:     0x8
		// Field Name: fooField
		//

		StringBuilder buffy = new StringBuilder(HTMLUtilities.HTML);

		//@formatter:off
		buffy.append("<TABLE>");
		buffy.append(
			row("Parent: ",	HTMLUtilities.friendlyEncodeHTML(parentType.getName())));
		buffy.append(
			row("Offset: ", NumericUtilities.toHexString(offset)));
		buffy.append(
			row("Field Name: ", HTMLUtilities.friendlyEncodeHTML(token.getText())));
		buffy.append("</TABLE>");
		//@formatter:on

		if (fieldType != null) {
			buffy.append(HTMLUtilities.BR).append("<HR WIDTH=\"95%\">").append(HTMLUtilities.BR);
			buffy.append(ToolTipUtils.getHTMLRepresentation(fieldType).getFullHTMLContentString());
		}

		return buffy.toString();
	}

	private String row(String... cols) {
		StringBuilder sb = new StringBuilder("<TR>");
		for (String col : cols) {
			sb.append("<TD>").append(col).append("</TD>");
		}
		sb.append("</TR>");
		return sb.toString();
	}

	public static DataType getFieldDataType(ClangFieldToken field) {
		DataType fieldDt = DataTypeUtils.getBaseDataType(field.getDataType());
		if (fieldDt instanceof Structure) {
			Structure parent = (Structure) fieldDt;
			int offset = field.getOffset();
			int n = parent.getLength();
			if (offset >= 0 && offset < n) {
				DataTypeComponent dtc = parent.getComponentAt(offset);
				if (dtc == null) {
					return null;
				}
				fieldDt = dtc.getDataType();
			}
		}
		return fieldDt;
	}
}
