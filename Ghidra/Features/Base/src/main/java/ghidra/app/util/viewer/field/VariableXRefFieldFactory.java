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
import java.util.*;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.XReferenceUtil;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableXRefFieldLocation;

/**
 * Variable Cross-reference Field Factory
 * <br>
 *
 */
public class VariableXRefFieldFactory extends XRefFieldFactory {

	@SuppressWarnings("hiding")
	// yes, bad, change it if you wish
	public static final String FIELD_NAME = "Variable XRef";

	/**
	 * Constructor
	 */
	public VariableXRefFieldFactory() {
		this(FIELD_NAME);
	}

	protected VariableXRefFieldFactory(String name) {
		super(name);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HighlightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public VariableXRefFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, ToolOptions fieldOptions) {
		this(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
	}

	protected VariableXRefFieldFactory(String name, FieldFormatModel model,
			HighlightProvider hlProvider, Options displayOptions, ToolOptions fieldOptions) {
		super(name, model, hlProvider, displayOptions, fieldOptions);
		colorOptionName = "XRef Color";
		styleOptionName = "XRef Style";
		initDisplayOptions();
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getField(ProxyObj, int)
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || obj == null || !(obj instanceof Variable)) {
			return null;
		}

		Variable var = (Variable) obj;
		List<Reference> xrefs = new ArrayList<>();
		List<Reference> offcuts = new ArrayList<>();
		XReferenceUtil.getVariableRefs(var, xrefs, offcuts);

		if (xrefs.size() + offcuts.size() == 0) {
			return null;
		}

		Function func = var.getFunction();
		Program program = func.getProgram();

		// Note: These should always be false since the only references
		//       to stack vars are from inside one functions and memory block.
		displayLocalNamespace = false; //provider.isDisplayFunctionName();
		displayBlockName = false; //provider.isDisplayBlockName();

		int totalXrefs = xrefs.size() + offcuts.size();
		boolean tooMany = totalXrefs > maxXRefs;

		AttributedString delimiter = new AttributedString(delim, Color.BLACK, getMetrics());

		FieldElement[] elements = new FieldElement[tooMany ? maxXRefs : totalXrefs];
		int count = 0;

		for (; count < xrefs.size() && count < elements.length; count++) {
			Reference reference = xrefs.get(count);
			String prefix = getPrefix(program, reference, func);
			AttributedString as = new AttributedString(reference.getFromAddress().toString(prefix),
				color, getMetrics());
			if (displayRefType) {
				as = createRefTypeAttributedString(reference, as);
			}
			if (count < totalXrefs - 1) {
				as = new CompositeAttributedString(new AttributedString[] { as, delimiter });
			}
			else {
				// This added to prevent a situation where resizing field to a particular size, resulted in layout of references to be strange
				char[] charSpaces = new char[delimiter.length()];
				Arrays.fill(charSpaces, ' ');
				AttributedString spaces =
					new AttributedString(new String(charSpaces), color, getMetrics());
				as = new CompositeAttributedString(new AttributedString[] { as, spaces });
			}
			elements[count] = new TextFieldElement(as, count, 0);
		}

		for (int i = 0; i < offcuts.size() && count < elements.length; i++, count++) {
			Reference ref = offcuts.get(i);
			String prefix = getPrefix(program, ref, func);
			AttributedString as = new AttributedString(ref.getFromAddress().toString(prefix),
				offcutColor, getMetrics());
			if (displayRefType) {
				as = createRefTypeAttributedString(ref, as);
			}
			if (count < totalXrefs - 1) {
				as = new CompositeAttributedString(new AttributedString[] { as, delimiter });
			}
			else {
				// This added to prevent a situation where resizing field to a particular size, resulted in layout of references to be strange
				char[] charSpaces = new char[delimiter.length()];
				Arrays.fill(charSpaces, ' ');
				AttributedString spaces =
					new AttributedString(new String(charSpaces), offcutColor, getMetrics());
				as = new CompositeAttributedString(new AttributedString[] { as, spaces });
			}
			elements[count] = new TextFieldElement(as, count, 0);
		}

		if (tooMany) {
			AttributedString as = new AttributedString("[more]", color, getMetrics());
			elements[count - 1] = new TextFieldElement(as, count - 1, 0);
		}

		return ListingTextField.createPackedTextField(this, proxy, elements, startX + varWidth,
			width, maxXRefs, hlProvider);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (!(loc instanceof VariableXRefFieldLocation)) {
			return null;
		}

		Object obj = bf.getProxy().getObject();
		if (obj instanceof Variable) {
			Variable sv = (Variable) obj;
			VariableXRefFieldLocation varXRefLoc = (VariableXRefFieldLocation) loc;
			if (varXRefLoc.isLocationFor(sv)) {
				return createFieldLocation(varXRefLoc.getCharOffset(), varXRefLoc.getIndex(),
					(ListingTextField) bf, index, fieldNum);
			}
		}

		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof Variable)) {
			return null;
		}

		ListingTextField field = (ListingTextField) getField(bf.getProxy(), 0);

		if (field != null) {
			RowColLocation loc = field.screenToDataLocation(row, col);
			int index = loc.row();

			Variable var = (Variable) obj;
			List<Reference> xrefs = new ArrayList<>();
			List<Reference> offcuts = new ArrayList<>();
			XReferenceUtil.getVariableRefs(var, xrefs, offcuts);

			Reference ref = null;
			if (index < xrefs.size()) {
				ref = xrefs.get(index);
			}
			else if (index < xrefs.size() + offcuts.size()) {
				ref = offcuts.get(index - xrefs.size());
			}
			if (ref != null) {
				Address refAddr = ref.getFromAddress();
				return new VariableXRefFieldLocation(var.getProgram(), var, refAddr, index,
					loc.col());
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
		return new VariableXRefFieldFactory(formatModel, provider, displayOptions, fieldOptions);
	}
}
