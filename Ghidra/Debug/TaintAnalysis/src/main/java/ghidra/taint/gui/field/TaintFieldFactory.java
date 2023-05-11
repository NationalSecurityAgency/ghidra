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
package ghidra.taint.gui.field;

import java.math.BigInteger;

import docking.widgets.fieldpanel.field.AttributedString;
import docking.widgets.fieldpanel.field.TextFieldElement;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GColor;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.pcode.emu.taint.trace.TaintTracePcodeExecutorStatePiece;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.program.util.ProgramLocation;
import ghidra.taint.model.TaintSet;
import ghidra.taint.model.TaintVec;

/**
 * A field factory for "Taint" in the Listing panels
 * 
 * <p>
 * This implements an interface that is part of the core framework, even lower than the Debugger
 * framework. I used the "sample" module's {@code EntropyFieldFactory} for reference.
 */
public class TaintFieldFactory extends FieldFactory {
	public static final String PROPERTY_NAME = TaintTracePcodeExecutorStatePiece.NAME;
	public static final GColor COLOR = new GColor("color.fg.listing.taint");
	public static final String FIELD_NAME = "Taint";

	public TaintFieldFactory() {
		super(FIELD_NAME);
	}

	protected TaintFieldFactory(FieldFormatModel formatModel, ListingHighlightProvider highlightProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, formatModel, highlightProvider, displayOptions, fieldOptions);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel,
			ListingHighlightProvider highlightProvider, ToolOptions displayOptions,
			ToolOptions fieldOptions) {
		return new TaintFieldFactory(formatModel, highlightProvider, displayOptions, fieldOptions);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This is where the most of the rendering logic is. Here, we access the property map and
	 * deserialize into a {@link TaintVec} manually (as compared to using a state piece as we did in
	 * {@link TaintDebuggerRegisterColumnFactory}). Once we have the complete vector, we render it
	 * for display.
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		StringPropertyMap taintMap =
			cu.getProgram().getUsrPropertyManager().getStringPropertyMap(PROPERTY_NAME);
		if (taintMap == null) {
			return null;
		}

		TaintVec vec = new TaintVec(cu.getLength());
		for (int i = 0; i < vec.length; i++) {
			String taintString = taintMap.getString(cu.getAddress().add(i));
			vec.set(i, taintString == null ? TaintSet.EMPTY : TaintSet.parse(taintString));
		}

		return ListingTextField.createSingleLineTextField(this, proxy,
			new TextFieldElement(new AttributedString(vec.toDisplay(), COLOR, getMetrics()), 0, 0),
			startX + varWidth, width, hlProvider);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the core framework provides an API for accessing and manipulating the user's cursor,
	 * we have to provide a means to distinguish locations in our field from others. This method
	 * provides on direction of the conversion between field and program locations.
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (!(loc instanceof TaintFieldLocation)) {
			return null;
		}
		TaintFieldLocation tfLoc = (TaintFieldLocation) loc;
		return new FieldLocation(index, fieldNum, 0, tfLoc.getCharOffset());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Because the core framework provides an API for accessing and manipulating the user's cursor,
	 * we have to provide a means to distinguish locations in our field from others. This method
	 * provides on direction of the conversion between field and program locations.
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		Object obj = proxy.getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		return new TaintFieldLocation(proxy.getListingLayoutModel().getProgram(), cu.getAddress(),
			col);
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA);
	}
}
