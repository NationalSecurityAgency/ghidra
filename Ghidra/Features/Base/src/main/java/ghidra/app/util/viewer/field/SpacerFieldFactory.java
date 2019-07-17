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

import docking.widgets.OptionDialog;
import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.SpacerFieldLocation;
import ghidra.util.StringUtilities;
import ghidra.util.classfinder.ClassSearcher;

/**
  *  Generates Spacer Fields.
  *  <P> 
  *  This field is not meant to be loaded by the {@link ClassSearcher}, hence the X in the name.
  */
public class SpacerFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Spacer";
	private String text = null;

	/**
	 * Constructor
	 */
	public SpacerFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hsProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private SpacerFieldFactory(FieldFormatModel model, HighlightProvider hsProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hsProvider, displayOptions, fieldOptions);
	}

	/**
	 * Constructor
	 * @param text The text to display in the field.
	 * @param model The Field model that will use this Address factory.
	 * @param hsProvider the HightLightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	  */
	public SpacerFieldFactory(String text, FieldFormatModel model, HighlightProvider hsProvider,
			Options displayOptions, Options fieldOptions) {

		super(FIELD_NAME, model, hsProvider, displayOptions, fieldOptions);
		this.text = text;
	}

	/**
	 * Sets the text for the spacer field
	 * @param text the text to display in the listing
	 */
	public void setText(String text) {
		if (text != null && text.length() == 0) {
			text = null;
		}
		this.text = text;
	}

	/**
	 * Sets the literal text to display in this field.
	 */
	public void setText() {
		String newText =
			OptionDialog.showInputSingleLineDialog(null, "Input Spacer Text", "Text", text);
		if (newText != null) {
			newText = newText.trim();
			if (newText.equals("")) {
				text = null;
			}
			else {
				text = newText;
			}
		}
		model.update();
	}

	/**
	 * Returns the spacer field's text
	 */
	public String getText() {
		return text;
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		if (enabled && (text != null)) {
			AttributedString as = new AttributedString(text, color, getMetrics());
			FieldElement field = new TextFieldElement(as, 0, 0);
			return ListingTextField.createSingleLineTextField(this, proxy, field, startX + varWidth,
				width, hlProvider);

		}
		return null;
	}

	@Override
	public String getFieldText() {
		if (text == null) {
			return "";
		}
		return text;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {
		if (!(programLoc instanceof SpacerFieldLocation)) {
			return null;
		}

		SpacerFieldLocation loc = (SpacerFieldLocation) programLoc;
		if (loc.getText().equals(text)) {
			return new FieldLocation(index, fieldNum, 0, loc.getCharOffset());
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		int[] cpath = null;
		if (obj instanceof Data) {
			cpath = ((Data) obj).getComponentPath();
		}

		return new SpacerFieldLocation(cu.getProgram(), cu.getMinAddress(), cpath, col, text);
	}

	/**
	 * Returns the string to highlight
	 * @param bf the ListingTextField
	 * @param row the row in the field
	 * @param col the column in the field
	 * @param loc the programLocation.
	 */
	public String getStringToHighlight(ListingTextField bf, int row, int col, ProgramLocation loc) {
		if (loc == null) {
			return null;
		}
		String s = ((SpacerFieldLocation) loc).getText();
		return StringUtilities.findWord(s, col);
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return true;
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions options, ToolOptions fieldOptions) {
		return new SpacerFieldFactory(formatModel, provider, options, fieldOptions);
	}

}
