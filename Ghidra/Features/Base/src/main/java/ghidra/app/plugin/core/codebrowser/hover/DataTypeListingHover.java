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
package ghidra.app.plugin.core.codebrowser.hover;

import javax.swing.JComponent;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.hover.AbstractConfigurableHover;
import ghidra.app.util.ToolTipUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Equate;
import ghidra.program.util.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.UniversalID;

public class DataTypeListingHover extends AbstractConfigurableHover implements ListingHoverService {

	private static final String NAME = "Data Type Display";
	private static final String DESCRIPTION =
		"Toggle whether data type contents are displayed in a tooltip " +
			"when the mouse hovers over a data type.";
	private static final int PRIORITY = 20;

	public DataTypeListingHover(PluginTool tool) {
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
		return GhidraOptions.CATEGORY_BROWSER_POPUPS;
	}

	@Override
	public JComponent getHoverComponent(Program program, ProgramLocation programLocation,
			FieldLocation fieldLocation, Field field) {

		if (!enabled || programLocation == null) {
			return null;
		}

		DataType dt = null;
		Data dataInstance = null;
		Integer dataLen = null;
		boolean hasInvalidStorage = false;

		if (programLocation instanceof VariableLocation) {
			if (programLocation instanceof VariableCommentFieldLocation) {
				return null;// no Data Type tooltip here
			}
			Variable var = ((VariableLocation) programLocation).getVariable();
			if (var != null) {
				dt = var.getDataType();
				hasInvalidStorage = !var.isValid();
			}
		}
		else if (programLocation instanceof MnemonicFieldLocation) {
			dataInstance = getDataForLocation(program, programLocation);
			if (dataInstance != null) {
				dt = dataInstance.getDataType();
				if (dt.getLength() < 0) {
					dataLen = dataInstance.getLength();
				}
			}
		}
		else if (programLocation instanceof FunctionReturnTypeFieldLocation) {
			dt = getFunctionReturnDataType(program, programLocation.getAddress());
		}

		if (dt != null) {
			String toolTipText = ToolTipUtils.getToolTipText(dt);
			if (dataLen != null) {
				// NOTE: "Unsized" matches with literal string in DefaultDataTypeHTMLRepresentation.buildFooter()
				toolTipText = toolTipText.replace("Unsized", Integer.toString(dataLen));
			}
			if (dataInstance != null) {
				toolTipText = toolTipText.replace("</HTML>",
					getLocationSupplimentalToolTipText(dt, dataInstance) + "</HTML>");
			}
			String warningMsg = "";
			if (hasInvalidStorage) {
				warningMsg += "WARNING! Invalid Storage";
			}
			if (warningMsg.length() != 0) {
				String errorText =
					"<HTML><center><font color=\"red\">" + warningMsg + "!</font></center><BR>";
				toolTipText = toolTipText.replace("<HTML>", errorText);
			}
			return createTooltipComponent(toolTipText);
		}

		// no data type
		if (programLocation instanceof EquateOperandFieldLocation) {
			// I know, I know, an equate is not a data type.  Rather than create a new hover
			// provider just for equates, I thought it good enough to put the code here.
			EquateOperandFieldLocation equateLocation =
				(EquateOperandFieldLocation) programLocation;
			return createEquateToolTipComponent(program, equateLocation.getEquate());
		}

		return null;
	}

	private String getLocationSupplimentalToolTipText(DataType dt, Data dataInstance) {
		String result = "";
		if (dt instanceof DataTypeWithCharset) {
			String charset = ((DataTypeWithCharset) dt).getCharsetName(dataInstance);
			result = String.format("<br>Charset: %s", charset);
		}
		if (StringDataInstance.isString(dataInstance)) {
			StringDataInstance sdi = StringDataInstance.getStringDataInstance(dataInstance);
			if (sdi.isShowTranslation()) {
				result += String.format("<br>Original value: %s",
					HTMLUtilities.friendlyEncodeHTML(sdi.getStringValue()));
			}
			if (!sdi.isShowTranslation() && sdi.getTranslatedValue() != null) {
				result += String.format("<br>Translated value: %s",
					HTMLUtilities.friendlyEncodeHTML(sdi.getTranslatedValue()));
			}
			if (sdi.isMissingNullTerminator()) {
				result += "<br>Missing NULL terminator.";
			}
			if (sdi.getStringLength() > dataInstance.getLength()) {
				result += "<br><font color=\"red\">String exceeds data field.</font>";
			}
		}
		return result;
	}

	private Data getDataForLocation(Program program, ProgramLocation location) {
		Listing listing = program.getListing();
		Address address = location.getAddress();
		Data data = listing.getDataContaining(address);
		if (data != null) {
			return data.getComponent(location.getComponentPath());
		}
		return null;
	}

	private DataType getFunctionReturnDataType(Program program, Address address) {
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(address);
		if (function != null) {
			return function.getReturnType();
		}

		return null;
	}

	private JComponent createEquateToolTipComponent(Program program, Equate equate) {
		StringBuilder hoverInfo = new StringBuilder();
		if (equate.isEnumBased() && equate.isValidUUID()) {
			DataTypeManager dtm = program.getDataTypeManager();
			UniversalID id = equate.getEnumUUID();
			Enum enoom = (Enum) dtm.findDataTypeForID(id);
			if (enoom != null) {
				hoverInfo.append("<html>Equate value: " + equate.getDisplayValue() + "<hr>" +
					ToolTipUtils.getHTMLRepresentation(enoom).getHTMLContentString() + "</html>");
			}
		}
		else {
			hoverInfo.append(equate.getDisplayValue());
		}
		return createTooltipComponent(hoverInfo.toString());
	}

}
