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
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DividerLocation;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates Separator Fields.
  */
public class SeparatorFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Separator";
	private static final char sepChar = '.';
	StringBuffer sb = new StringBuffer();

	/**
	 * Constructor
	 */
	public SeparatorFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private SeparatorFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getField(ProxyObj, int)
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		if (!enabled) {
			return null;
		}
		int numChars = width / getMetrics().charWidth(sepChar);
		sb.setLength(0);
		for (int i = 0; i < numChars; i++) {
			sb.append(sepChar);
		}

		AttributedString as = new AttributedString(sb.toString(), color, getMetrics());
		FieldElement text = new TextFieldElement(as, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, text, startX + varWidth,
			width, hlProvider);

	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (obj instanceof Address) {
			ListingModel layoutModel = bf.getProxy().getListingLayoutModel();
			Program program = layoutModel.getProgram();
			return new DividerLocation(program, (Address) obj, null, col);
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {
		if (programLoc instanceof DividerLocation) {
			return new FieldLocation(index, fieldNum, 0,
				((DividerLocation) programLoc).getCharOffset());
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (category == FieldFormatModel.DIVIDER);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new SeparatorFieldFactory(formatModel, provider, displayOptions, fieldOptions);
	}

}
