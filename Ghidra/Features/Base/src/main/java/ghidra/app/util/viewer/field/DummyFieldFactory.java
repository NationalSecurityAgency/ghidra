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
import ghidra.app.util.viewer.format.FormatManager;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.ToolOptions;
import ghidra.program.util.ProgramLocation;

/**
  *  Generates Dummy Fields.
  */
public class DummyFieldFactory extends FieldFactory {

	public DummyFieldFactory(FormatManager mgr) {
		super("Dummy", mgr.getDividerModel(), mgr.getFormatHighlightProvider(),
			mgr.getDisplayOptions(), mgr.getFieldOptions());
	}

	@Override
	public String getFieldName() {
		return "Dummy";
	}

	@Override
	public String getFieldText() {
		return "The Dummy Field";
	}

	@Override
	public ListingField getField(ProxyObj<?> obj, int varWidth) {
		if (!enabled || obj == null) {
			return null;
		}
		int x = startX + varWidth;
		FieldElement text =
			new TextFieldElement(new AttributedString("", color, getMetrics()), 0, 0);

		return ListingTextField.createSingleLineTextField(this, obj, text, x, width, hlProvider);
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return false;
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (loc.getClass() == ProgramLocation.class) {
			return new FieldLocation(index, fieldNum, 0, 0);
		}

		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		return null;
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider hlProvdier,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return this;
	}
}
