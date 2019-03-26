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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.Color;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.plugin.core.navigation.FunctionUtils;
import ghidra.app.util.viewer.field.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.FunctionLocation;
import ghidra.program.util.FunctionParameterNameFieldLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

class FunctionParameterNameLocationDescriptor extends FunctionSignatureFieldLocationDescriptor {

	FunctionParameterNameLocationDescriptor(FunctionLocation location, Program program) {
		super(location, program);
	}

	@Override
	protected void init() {
		validate((FunctionLocation) programLocation);
		homeAddress = programLocation.getAddress();
		label = getVariableName();
	}

	@Override
	protected void validate(FunctionLocation location) {
		if (location == null) {
			throw new NullPointerException(
				"Cannot create a LocationDescriptor from a null " + "ProgramLocation");
		}

		if (!(programLocation instanceof FunctionParameterNameFieldLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + programLocation);
		}
	}

	protected Variable getVariable() {
		return ((FunctionParameterNameFieldLocation) programLocation).getParameter();
	}

	protected String getVariableName() {
		return ((FunctionParameterNameFieldLocation) programLocation).getParameterName();
	}

	@Override
	protected void doGetReferences(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		Variable variable = getVariable();
		if (variable == null) {
			// Not sure why, but sometimes a VariableLocation can return a null variable
			return;
		}
		ReferenceUtils.getVariableReferences(accumulator, program, variable);
	}

	@Override
	Highlight[] getHighlights(String text, Object object,
			Class<? extends FieldFactory> fieldFactoryClass, Color highlightColor) {

		Address currentAddress = getAddressForHighlightObject(object);
		if (!isInAddresses(currentAddress)) {
			return EMPTY_HIGHLIGHTS;
		}

		if (OperandFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			int offset = text.indexOf(label);
			if (offset >= 0) {
				return new Highlight[] {
					new Highlight(offset, label.length() + offset - 1, highlightColor) };
			}
		}
		else if (VariableNameFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			if (label.equals(text)) {
				return new Highlight[] { new Highlight(0, text.length() - 1, highlightColor) };
			}
		}
		else if (FunctionSignatureFieldFactory.class.isAssignableFrom(fieldFactoryClass)) {
			// pull out the matching pieces of the data type
			List<Highlight> list = new ArrayList<>();

			Function functionObject = (Function) object;
			FieldStringInfo[] parameterStringInfos =
				FunctionUtils.getFunctionParameterStringInfos(functionObject, text);
			for (FieldStringInfo info : parameterStringInfos) {
				String paramString = info.getFieldString();
				String paramName = paramString.split("\\s")[1];
				if (label.equals(paramName)) {
					int offset = info.getOffset() + paramString.indexOf(paramName);
					int length = offset + paramName.length() - 1;
					list.add(new Highlight(offset, length, highlightColor));
				}
			}

			return list.toArray(new Highlight[list.size()]);
		}

		return EMPTY_HIGHLIGHTS;
	}
}
