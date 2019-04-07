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
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.app.util.viewer.proxy.VariableProxy;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.VariableXRefHeaderFieldLocation;

/**
 * Field for showing Xref Headers for variables
 */
public class VariableXRefHeaderFieldFactory extends VariableXRefFieldFactory {

	@SuppressWarnings("hiding")
	// yes, bad, change it if you wish
	private static final String FIELD_NAME = "Variable XRef Header";

	public VariableXRefHeaderFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HighlightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public VariableXRefHeaderFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		colorOptionName = "XRef Color";
		styleOptionName = "XRef Style";
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

		String headString = getXRefHeaderString(obj);
		if (headString == null || headString.length() == 0) {
			return null;
		}

		AttributedString as = new AttributedString(headString, color, getMetrics());
		FieldElement text = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, text, startX + varWidth,
			width, hlProvider);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (!(loc instanceof VariableXRefHeaderFieldLocation)) {
			return null;
		}

		Object obj = bf.getProxy().getObject();
		if (obj instanceof Variable) {
			Variable sv = (Variable) obj;
			VariableXRefHeaderFieldLocation xRefHeaderLoc = (VariableXRefHeaderFieldLocation) loc;
			if (xRefHeaderLoc.isLocationFor(sv)) {
				return new FieldLocation(index, fieldNum, xRefHeaderLoc.getIndex(),
					xRefHeaderLoc.getCharOffset());
			}
		}
		return null;
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
			return new VariableXRefHeaderFieldLocation(sv.getProgram(), sv, col, null);
		}
		return null;
	}

	/**
	 * Creates a field with "XREF[m,n]:"
	 * <br>
	 * Where:<br>
	 *      m is the number of cross references <br>
	 *      n is the number of off-cut cross references <br><br>
	 */
	private String getXRefHeaderString(Object obj) {
		if (obj == null || !(obj instanceof Variable)) {
			return null;
		}
		Variable var = (Variable) obj;

		int xrefCount = 0;
		int offcutCount = 0;
		Varnode varnode = var.getFirstStorageVarnode();
		if (varnode == null) {
			return null;
		}
		Address varAddr = varnode.getAddress();
		Program program = var.getFunction().getProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] vrefs = refMgr.getReferencesTo(var);
		for (Reference vref : vrefs) {
			if (vref.getToAddress().equals(varAddr)) {
				xrefCount++;
			}
			else {
				offcutCount++;
			}
		}

		if (xrefCount > 0 || offcutCount > 0) {
			if (offcutCount > 0) {
				return "XREF[" + xrefCount + "," + offcutCount + "]:";
			}
			return "XREF[" + xrefCount + "]:";
		}
		return null;
	}

	/*
	 *  (non-Javadoc)
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
		return new VariableXRefHeaderFieldFactory(formatModel, provider, displayOptions,
			fieldOptions);
	}
}
