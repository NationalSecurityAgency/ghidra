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
import java.math.BigInteger;
import java.util.ArrayList;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.*;
import ghidra.program.util.AssignedVariableLocation;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates Variable Assignment Fields (point of first-use).
  */
public class AssignedVariableFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Var Assign";
	public static final Color DEFAULT_COLOR = new Color(128, 0, 128);

	/**
	 * Default constructor.
	 */
	public AssignedVariableFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private AssignedVariableFieldFactory(FieldFormatModel model, HighlightProvider hsProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hsProvider, displayOptions, fieldOptions);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

	}

//	private static String getOffsetString(int offset) {
//		String offString =
//			(offset >= 0 ? Integer.toHexString(offset) : "-" + Integer.toHexString(-offset));
//		return offString;
//	}

	/**
	 * Returns the FactoryField for the given object at index index.
	 * @param varWidth the amount of variable width spacing for any fields
	 * before this one.
	 * @param proxy the object whose properties should be displayed.
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		ArrayList<FieldElement> elemenetList = new ArrayList<>();

		Function f = cu.getProgram().getFunctionManager().getFunctionContaining(cu.getMinAddress());
		if (f != null) {

			int minOffset = (int) (cu.getMinAddress().getOffset() - f.getEntryPoint().getOffset());
			int maxOffset = minOffset + cu.getLength() - 1;

			Variable[] vars = f.getLocalVariables();
			for (Variable var : vars) {
				int firstUseOffset = var.getFirstUseOffset();
				if (firstUseOffset != 0 && firstUseOffset >= minOffset &&
					firstUseOffset <= maxOffset) {
					StringBuffer buf = new StringBuffer("assign ");
					buf.append(var.getVariableStorage().toString());
					buf.append(" = ");
					buf.append(var.getName());
					AttributedString as = new AttributedString(buf.toString(), color, getMetrics());
					elemenetList.add(new TextFieldElement(as, 0, 0));
				}
			}
		}
		if (elemenetList.size() == 0) {
			return null;
		}

		FieldElement[] elements = new FieldElement[elemenetList.size()];
		elemenetList.toArray(elements);

		return ListingTextField.createMultilineTextField(this, proxy, elements, startX + varWidth,
			width, elements.length + 1, hlProvider);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		return new AssignedVariableLocation(cu.getProgram(), cu.getMinAddress(), row, col);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		if (programLoc instanceof AssignedVariableLocation) {
			AssignedVariableLocation loc = (AssignedVariableLocation) programLoc;
			return new FieldLocation(index, fieldNum, loc.getRow(), loc.getCharOffset());
		}
		return null;
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider hsProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new AssignedVariableFieldFactory(formatModel, hsProvider, displayOptions,
			fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return DEFAULT_COLOR;
	}
}
