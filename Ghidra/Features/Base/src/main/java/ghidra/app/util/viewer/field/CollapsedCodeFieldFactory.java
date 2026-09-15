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
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.proxy.CodeUnitProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.CollapsedCodeLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Generates field to indicate collapsed function for areas of hidden code.
 */
public class CollapsedCodeFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Collapsed Code";

	public CollapsedCodeFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private CollapsedCodeFieldFactory(FieldFormatModel model, ListingHighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		if (!enabled || !(proxy instanceof CodeUnitProxy cuProxy)) {
			return null;
		}
		CodeUnit cu = cuProxy.getObject();
		Address address = cu.getAddress();
		Function function = cu.getProgram().getListing().getFunctionContaining(address);
		if (function == null) {
			return null;
		}
		String text = "<Collapsed: " + function.getName() + "()>";
		AttributedString s = new AttributedString(text, ListingColors.COLLAPSED_CODE, getMetrics());
		FieldElement element = new TextFieldElement(s, 0, 0);
		return ListingTextField.createSingleLineTextField(this, cuProxy, element, startX + varWidth,
			width, hlProvider);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (obj instanceof CodeUnit cu) {
			Address address = cu.getAddress();
			ListingModel layoutModel = bf.getProxy().getListingLayoutModel();
			Program program = layoutModel.getProgram();
			return new CollapsedCodeLocation(program, address);
		}
		return null;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {
		if (programLoc instanceof CollapsedCodeLocation) {
			return new FieldLocation(index, fieldNum, 0, 0);
		}
		return null;
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		// this factory only appears in the header DIVIDER tab (which is called "Address Break" in
		// the gui)
		return category == FieldFormatModel.DIVIDER;
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, ListingHighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new CollapsedCodeFieldFactory(formatModel, provider, displayOptions, fieldOptions);
	}
}
