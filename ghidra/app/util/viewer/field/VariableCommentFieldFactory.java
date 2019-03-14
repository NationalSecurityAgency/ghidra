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
import ghidra.program.util.VariableCommentFieldLocation;
import ghidra.util.StringUtilities;

/**
  *  Generates StackVariableComment Fields.
  */
public class VariableCommentFieldFactory extends AbstractVariableFieldFactory {
	public static final String FIELD_NAME = "Variable Comment";

	/**
	 * Constructor
	 */
	public VariableCommentFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private VariableCommentFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
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
		Variable sv = (Variable) obj;
		String comment = sv.getComment();
		String[] comments = StringUtilities.toLines(comment);
		if ((comments != null) && (comments.length > 0)) {
			FieldElement[] fields = new FieldElement[comments.length];
			for (int i = 0; i < comments.length; i++) {
				AttributedString as =
					new AttributedString(comments[i], getColor(sv), getMetrics(sv));
				fields[i] = new TextFieldElement(as, i, 0);
			}

			return ListingTextField.createMultilineTextField(this, proxy, fields, startX + varWidth,
				width, Integer.MAX_VALUE, hlProvider);
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int,
	 *      int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof VariableProxy) {

			VariableProxy variableProxy = (VariableProxy) proxy;
			Variable sv = variableProxy.getObject();
			ListingTextField btf = (ListingTextField) bf;

			String cmt = sv.getComment();

			// Loop through each line of the comment
			// and store the length of the line.
			// Additionally, we need to store the length of
			// the delimiter between the lines. Otherwise,
			// the index in the ProgramLocation will be off.
			//
			int pos = 0;
			int tmp = 0;
			for (int i = 0; i <= row; ++i) {
				String str = btf.getFieldElement(i, 0).getText();
				int len = 0;
				if (i < row) {
					len = str.length();
				}
				else {
					len = col;
				}
				pos += len;

				int index = cmt.indexOf(str, tmp);
				if (tmp != 0) {
					pos += (index - tmp);
				}
				tmp = index + len;
			}

			return new VariableCommentFieldLocation(sv.getProgram(),
				variableProxy.getLocationAddress(), sv, pos);
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (!(loc instanceof VariableCommentFieldLocation)) {
			return null;
		}

		Object obj = bf.getProxy().getObject();
		if (obj instanceof Variable) {
			Variable sv = (Variable) obj;
			VariableCommentFieldLocation varCommentLoc = (VariableCommentFieldLocation) loc;
			if (varCommentLoc.isLocationFor(sv)) {
				int col = varCommentLoc.getCharOffset();
				ListingTextField btf = (ListingTextField) bf;
				int row = 0;
				for (; row < btf.getNumRows(); ++row) {
					FieldElement element = ((ListingTextField) bf).getFieldElement(row, 0);
					int len = element.length();
					if (len > col) {
						break;
					}
					col -= len;
				}
				return new FieldLocation(index, fieldNum, row, col);
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
		return new VariableCommentFieldFactory(formatModel, provider, displayOptions, fieldOptions);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getDefaultColor()
	 */
	@Override
	public Color getDefaultColor() {
		return OptionsGui.VARIABLE.getDefaultColor();
	}
}
