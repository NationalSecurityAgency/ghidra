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
package ghidra.app.plugin.core.equate;

import java.awt.Font;
import java.awt.FontMetrics;

import javax.swing.JMenuItem;

import docking.action.MenuData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;

public abstract class AbstractConvertAction extends ListingContextAction {
	protected final EquatePlugin plugin;
	private FontMetrics metrics;
	private final boolean isSigned;

	public AbstractConvertAction(EquatePlugin plugin, String actionName, boolean isSigned) {
		super(actionName, plugin.getName());
		this.plugin = plugin;
		this.isSigned = isSigned;
		setPopupMenuData(new MenuData(new String[] { "Convert", "" }, "Convert"));
		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ListingActionContext context) {
		ProgramLocation loc = context.getLocation();
		if (!(loc instanceof OperandFieldLocation)) {
			return false;
		}
		Scalar scalar = plugin.getScalar(context);
		if (scalar == null) {
			return false;
		}
		if (isSigned && scalar.getSignedValue() >= 0) {
			return false;
		}
		CodeUnit cu = plugin.getCodeUnit(context);
		if (cu instanceof Data) {
			if (getFormatChoice() == -1) {
				// unsupported data action
				return false;
			}
			Data data = (Data) cu;
			if (!data.isDefined()) {
				return false;
			}
			DataType dataType = data.getBaseDataType();
			if (!(dataType instanceof AbstractIntegerDataType)) {
				return false;
			}
		}
		String menuName = getMenuName(context.getProgram(), scalar, cu instanceof Data);
		if (menuName == null) {
			return false;
		}
		getPopupMenuData().setMenuItemName(menuName);
		return true;
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		// Let the command do all of the work.
		ConvertCommand cmd = new ConvertCommand(this, context);
		if (context.hasSelection()) {
			plugin.getTool().executeBackgroundCommand(cmd, context.getProgram());
		}
		else {
			plugin.getTool().execute(cmd, context.getProgram());
		}
	}

	/**
	 * Get the formatted menu item name.  Note that Data and Instructions may utilize different 
	 * numeric formatting conventions.
	 * @param program the program
	 * @param scalar the scalar value to be converted
	 * @param isData true if data selected, else false for instruction.
	 * @return formatted menu item name
	 */
	protected abstract String getMenuName(Program program, Scalar scalar, boolean isData);

	/**
	 * Get the formatted value string.  Note that Data and Instructions may utilize different 
	 * numeric formatting conventions.
	 * @param program the program
	 * @param scalar the scalar value to be converted
	 * @param isData true if data selected, else false for instruction.
	 * @return formatted value string
	 */
	protected abstract String convertToString(Program program, Scalar scalar, boolean isData);

	/**
	 * Get data settings {@link FormatSettingsDefinition} format
	 * @return data settings format, -1 if unsupported
	 */
	protected int getFormatChoice() {
		return -1;
	}

	/**
	 * Get the signed-ness to be supported.
	 * @return true if signed, else false if unsigned
	 */
	protected final boolean isSignedChoice() {
		return isSigned;
	}

	private int stringWidth(String s) {
		if (metrics == null) {
			JMenuItem item = new JMenuItem();
			Font font = item.getFont();
			metrics = plugin.getTool().getActiveWindow().getFontMetrics(font);
		}
		int w = metrics.stringWidth(s);
		if (w == 0) {
			// use default computation if metrics report 0
			return 10 * s.length();
		}
		return w;
	}

	String getStandardLengthString(String baseString) {
		int baseWidth = stringWidth(baseString);
		int spaceWidth = stringWidth(" ");
		int paddingSize = (140 - baseWidth) / spaceWidth;
		if (paddingSize <= 0) {
			return baseString;
		}
		StringBuilder buf = new StringBuilder(baseString);
		for (int i = 0; i < paddingSize; i++) {
			buf.append(" ");
		}
		return buf.toString();
	}
}
