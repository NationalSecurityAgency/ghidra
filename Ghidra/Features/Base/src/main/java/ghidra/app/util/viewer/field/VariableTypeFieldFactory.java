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

import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.app.util.viewer.proxy.VariableProxy;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableTypeFieldLocation;

/**
  *  Generates VariableType Fields.
  */
public class VariableTypeFieldFactory extends AbstractVariableFieldFactory {
	public static final String FIELD_NAME = "Variable Type";

	/**
	 * Constructor
	 */
	public VariableTypeFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private VariableTypeFieldFactory(FieldFormatModel model, ListingHighlightProvider hlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
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
		Variable variable = (Variable) obj;

		DataType dt;
		if (variable instanceof Parameter) {
			dt = ((Parameter) variable).getFormalDataType();
		}
		else {
			dt = variable.getDataType();
		}
		String dtName = getDataTypeName(dt);
		AttributedString as =
			new AttributedString(dtName, getColor(variable), getMetrics(variable));
		FieldElement field = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, field, startX + varWidth,
			width, hlProvider);
	}

	private String getDataTypeName(DataType dt) {
		if (dt == null) {
			return "";
		}
		String dtName = dt.getName();
		return dtName == null ? "" : simplifyTemplates(dtName);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof VariableProxy) {
			VariableProxy variableProxy = (VariableProxy) proxy;
			Variable sv = variableProxy.getObject();
			return new VariableTypeFieldLocation(sv.getProgram(),
				variableProxy.getLocationAddress(), sv, col);
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (!(loc instanceof VariableTypeFieldLocation)) {
			return null;
		}

		Object obj = bf.getProxy().getObject();
		if (obj instanceof Variable) {
			Variable sv = (Variable) obj;
			VariableTypeFieldLocation varTypeLoc = (VariableTypeFieldLocation) loc;
			if (varTypeLoc.isLocationFor(sv)) {
				return new FieldLocation(index, fieldNum, 0, varTypeLoc.getCharOffset());
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
	public FieldFactory newInstance(FieldFormatModel formatModel, ListingHighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new VariableTypeFieldFactory(formatModel, provider, displayOptions, fieldOptions);
	}
}
