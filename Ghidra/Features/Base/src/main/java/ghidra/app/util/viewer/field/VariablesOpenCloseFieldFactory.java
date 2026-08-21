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

import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.app.util.viewer.proxy.VariableProxy;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariablesOpenCloseLocation;

/**
  *  Generates Open/Close Fields for variables under functions.
  */
public class VariablesOpenCloseFieldFactory extends FieldFactory {

	public static final String FIELD_NAME = "+";

	public VariablesOpenCloseFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private VariablesOpenCloseFieldFactory(FieldFormatModel model,
			ListingHighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		servicesChanged();
	}

	/**
	 * Returns the FactoryField for the given object at index index.
	 * @param varWidth the amount of variable width spacing for any fields
	 * before this one.
	 * @param proxy the object whose properties should be displayed.
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {

		if (!enabled) {
			return null;
		}
		if (proxy instanceof VariableProxy variableProxy) {
			if (variableProxy.isFirst()) {
				return new VariableOpenCloseField(this, proxy, getMetrics(), startX + varWidth,
					width);
			}
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof VariableProxy variableProxy) {
			Program program = variableProxy.getProgram();
			Address functionAddress = variableProxy.getFunctionAddress();
			return new VariablesOpenCloseLocation(program, functionAddress);
		}
		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		if (!(programLoc instanceof VariablesOpenCloseLocation)) {
			return null;
		}
		return new FieldLocation(index, fieldNum, 0, 0);
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!Variable.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.FUNCTION_VARS);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel fieldModel, ListingHighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new VariablesOpenCloseFieldFactory(fieldModel, provider, displayOptions,
			fieldOptions);
	}
}
