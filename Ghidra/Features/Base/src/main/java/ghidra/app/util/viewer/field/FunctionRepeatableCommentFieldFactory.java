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

import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.FieldElement;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.FunctionProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.FunctionRepeatableCommentFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Field for showing Function repeatable comments
 */
public class FunctionRepeatableCommentFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Function Repeatable Comment";

	/**
	 * Default constructor
	 */
	public FunctionRepeatableCommentFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public FunctionRepeatableCommentFieldFactory(FieldFormatModel model,
			HighlightProvider hlProvider, Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof Function)) {
			return null;
		}
		int x = startX + varWidth;
		Function f = (Function) obj;
		Program program = f.getProgram();
		String[] commentArr = f.getRepeatableCommentAsArray();
		FieldElement[] fields = new FieldElement[commentArr.length];
		AttributedString prototype = new AttributedString("prototype", color, getMetrics());
		for (int i = 0; i < commentArr.length; i++) {
			fields[i] = CommentUtils.parseTextForAnnotations(commentArr[i], program, prototype, i);
		}

		if (commentArr.length > 0) {
			return ListingTextField.createMultilineTextField(this, proxy, fields, x, width,
				Integer.MAX_VALUE, hlProvider);
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		if (proxy instanceof FunctionProxy) {
			FunctionProxy functionProxy = (FunctionProxy) proxy;
			Function function = functionProxy.getObject();
			return new FunctionRepeatableCommentFieldLocation(function.getProgram(),
				functionProxy.getLocationAddress(), functionProxy.getFunctionAddress(),
				function.getRepeatableCommentAsArray(), row, col);
		}
		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (loc instanceof FunctionRepeatableCommentFieldLocation) {
			FunctionRepeatableCommentFieldLocation floc =
				(FunctionRepeatableCommentFieldLocation) loc;
			return new FieldLocation(index, fieldNum, floc.getRow(), floc.getCharOffset());
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!Function.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.FUNCTION);

	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions options, ToolOptions fieldOptions) {

		return new FunctionRepeatableCommentFieldFactory(formatModel, provider, options,
			fieldOptions);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getDefaultColor()
	 */
	@Override
	public Color getDefaultColor() {
		return OptionsGui.COMMENT_EOL.getDefaultColor();
	}
}
