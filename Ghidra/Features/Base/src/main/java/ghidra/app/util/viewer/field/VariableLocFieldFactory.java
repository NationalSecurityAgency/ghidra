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

import java.awt.Color;
import java.awt.FontMetrics;
import java.math.BigInteger;

import javax.swing.Icon;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.app.util.viewer.proxy.VariableProxy;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableLocFieldLocation;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.EmptyIcon;

/**
 *  Generates VariableOffset Fields.
 */
public class VariableLocFieldFactory extends AbstractVariableFieldFactory {
	public static final String FIELD_NAME = "Variable Location";
//
	private static final Icon INVALID_STORAGE_ICON =
		ResourceManager.loadImage("images/warning.png");

//	private static final Icon EMPTY_ICON = new EmptyIcon(20, 12);
//	private static Icon invalidStorageIcon;

	/**
	 * Constructor
	 */
	public VariableLocFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	* Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	*/
	private VariableLocFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {

		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
	}

	private Icon getStorageIcon(FontMetrics metrics, boolean isInvalid) {

		Icon icon = new EmptyIcon(18, metrics.getHeight());
		if (isInvalid) {
			icon = new MultiIcon(icon, INVALID_STORAGE_ICON);
		}
		return icon;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getField(ProxyObj, int)
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled || !(obj instanceof Variable)) {
			return null;
		}
		Variable var = (Variable) obj;
		FontMetrics fontMetrics = getMetrics(var);
		boolean hasInvalidStorage = !var.isValid();
		String loc = var.getVariableStorage().toString();
		AttributedString as = new AttributedString(getStorageIcon(fontMetrics, hasInvalidStorage),
			loc, hasInvalidStorage ? Color.RED : getColor(var), fontMetrics, false, null);
		FieldElement field = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, field, startX + varWidth,
			width, hlProvider);
	}

	/**
	 * Returns the string representing the offset.
	 * @param offset the offset to get a string for
	 */
	public String getOffsetString(int offset) {
		String offString =
			(offset >= 0 ? Integer.toHexString(offset) : "-" + Integer.toHexString(-offset));
		return offString;
	}

	/**
	 * 
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof VariableProxy) {
			VariableProxy variableProxy = (VariableProxy) proxy;
			Variable sv = variableProxy.getObject();
			return new VariableLocFieldLocation(sv.getProgram(), variableProxy.getLocationAddress(),
				variableProxy.getObject(), col);
		}

		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (!(loc instanceof VariableLocFieldLocation)) {
			return null;
		}

		Object obj = bf.getProxy().getObject();
		if (obj instanceof Variable) {
			Variable sv = (Variable) obj;
			VariableLocFieldLocation varStorageLoc = (VariableLocFieldLocation) loc;
			if (varStorageLoc.isLocationFor(sv)) {
				return new FieldLocation(index, fieldNum, 0, varStorageLoc.getCharOffset());
			}
		}

		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!Variable.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.FUNCTION_VARS);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new VariableLocFieldFactory(formatModel, provider, displayOptions, fieldOptions);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getDefaultColor()
	 */
	@Override
	public Color getDefaultColor() {
		return OptionsGui.VARIABLE.getDefaultColor();
	}
}
