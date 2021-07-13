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
import java.util.List;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.XReferenceUtils;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.XRefHeaderFieldLocation;

/**
 * Field for display XRef headers.
 */
public class XRefHeaderFieldFactory extends XRefFieldFactory {
	public static final String XREF_FIELD_NAME = "XRef Header";

	public XRefHeaderFieldFactory() {
		super(XREF_FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HighlightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public XRefHeaderFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, ToolOptions fieldOptions) {
		super(XREF_FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		colorOptionName = "XRef Color";
		styleOptionName = "XRef Style";
		initDisplayOptions();
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		String headString = getXRefHeaderString(cu);
		if (headString == null || headString.length() == 0) {
			return null;
		}
		AttributedString as = new AttributedString(headString, color, getMetrics());
		FieldElement field = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, field, startX + varWidth,
			width, hlProvider);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;
		int[] cpath = null;
		if (cu instanceof Data) {
			cpath = ((Data) cu).getComponentPath();
		}

		Address addr = cu.getMinAddress();
		return new XRefHeaderFieldLocation(cu.getProgram(), addr, cpath, col);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (!(loc instanceof XRefHeaderFieldLocation)) {
			return null;
		}

		XRefHeaderFieldLocation xRefLoc = (XRefHeaderFieldLocation) loc;
		if (xRefLoc.getRefAddress() != null) {
			return null;
		}

		if (!hasSamePath(bf, loc)) {
			return null;
		}

		return new FieldLocation(index, fieldNum, xRefLoc.getRow(), xRefLoc.getCharOffset());
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions options, ToolOptions fieldOptions) {
		return new XRefHeaderFieldFactory(formatModel, provider, options, fieldOptions);
	}

	/*
	 * Creates a field with "XREF[m,n]:"
	 * <br>
	 * Where:<br>
	 *      m is the number of cross references <br>
	 *      n is the number of off-cut cross references <br><br>
	 */
	private String getXRefHeaderString(CodeUnit cu) {
		if (cu == null) {
			return null;
		}
		Program prog = cu.getProgram();
		int xrefCount = prog.getReferenceManager().getReferenceCountTo(cu.getMinAddress());
		List<Reference> offcuts = XReferenceUtils.getOffcutXReferences(cu, maxXRefs);
		int offcutCount = offcuts.size();

		if (offcutCount > 0) {
			String modifier = "";
			if (offcutCount == maxXRefs) {
				modifier = "+";
			}
			return "XREF[" + xrefCount + "," + offcutCount + modifier + "]: ";
		}

		if (xrefCount > 0) {
			return "XREF[" + xrefCount + "]: ";
		}
		return null;
	}
}
