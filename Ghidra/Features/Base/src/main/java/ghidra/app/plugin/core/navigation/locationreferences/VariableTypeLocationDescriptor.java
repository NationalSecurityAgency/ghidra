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

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.util.viewer.field.FieldFactory;
import ghidra.app.util.viewer.field.VariableTypeFieldFactory;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.util.*;
import ghidra.util.exception.AssertException;

class VariableTypeLocationDescriptor extends DataTypeLocationDescriptor {

	VariableTypeLocationDescriptor(ProgramLocation location, Program program) {
		super(location, program);

		if (!(location instanceof VariableTypeFieldLocation)) {
			throw new AssertException("Unexpected ProgramLocation type - Cannot create a " +
				"LocationDescriptor for type: " + location);
		}
	}

	@Override
	protected String generateLabel() {
		return getDataTypeName();
	}

	@Override
	protected String getDataTypeName() {
		return originalDataType.getDisplayName();
	}

	@Override
	protected DataType getSourceDataType() {
		Variable var = ((VariableLocation) getLocation()).getVariable();
		return var.getDataType();
	}

	@Override
	protected DataType getBaseDataType() {
		return ReferenceUtils.getBaseDataType(getSourceDataType());
	}

	/**
	 * Overridden to catch special cases when processing variable locations.  This method will 
	 * call to the {@link super#getHighlights(String, Object, Class, Color)} 
	 *  <tt>super</tt> implementation if no variable highlights are found.
	 * 
	 * @see DataTypeLocationDescriptor#getHighlights(String, Object, Class, Color)
	 */
	@Override
	Highlight[] getHighlights(String text, Object object,
			Class<? extends FieldFactory> fieldFactoryClass, Color highlightColor) {
		if (VariableTypeFieldFactory.class.isAssignableFrom(fieldFactoryClass) &&
			(object instanceof Variable)) {
			// compare against the underlying datatype, since the display text is different
			Variable variable = (Variable) object;
			DataType otherBaseDataType = ReferenceUtils.getBaseDataType(variable.getDataType());
			if (otherBaseDataType.equals(baseDataType)) {
				return new Highlight[] { new Highlight(0, text.length() - 1, highlightColor) };
			}
		}

		return super.getHighlights(text, object, fieldFactoryClass, highlightColor);
	}
}
