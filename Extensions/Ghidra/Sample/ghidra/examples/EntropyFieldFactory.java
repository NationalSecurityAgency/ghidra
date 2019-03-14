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
package ghidra.examples;

import java.awt.Color;
import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.ProgramLocation;

public class EntropyFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "Entropy";
	StringBuffer sb = new StringBuffer();

	/**
	 * Constructor
	 */
	public EntropyFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	  * Constructor
	  * @param model the model that the field belongs to.
	  * @param hsProvider the HightLightStringProvider.
	  * @param displayOptions the Options for display properties.
	  * @param fieldOptions the Options for field specific properties.
	  */
	private EntropyFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
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

		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		byte[] bytes = null;
		double entropy = 0.0;
		try {
			bytes = new byte[256];
			int num = cu.getProgram().getMemory().getBytes(cu.getAddress(), bytes);
			if (num < bytes.length) {
				return null;
			}
			entropy = calcEntropy(bytes, 0, bytes.length);
			float[] hsbvals = Color.RGBtoHSB(255, 0, 0, null);
			color =
				Color.getHSBColor(hsbvals[0], hsbvals[1], (float) (hsbvals[1] * (entropy / 8.0)));
		}
		catch (MemoryAccessException e) {
			return null;
		}

		String str = "" + (int) ((entropy / 8.0) * 100);
		AttributedString text = new AttributedString(str, color, getMetrics());

		FieldElement fieldElement = new TextFieldElement(text, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, fieldElement,
			startX + varWidth, width, hlProvider);
	}

	private double calcEntropy(byte[] b, int start, int len) {
		float sum = 0;

		long[] countArray = new long[256];

		for (int i = start; i < (start + len); i++) {
			countArray[(b[i]) & 0xff] += 1;
		}

		for (long count : countArray) {
			if (count == 0) {
				continue;
			}
			double p_x = (double) count / (double) len;
			sum -= p_x * Math.log(p_x) * 1.0 / Math.log(2);
		}

		return sum;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		Object obj = bf.getProxy().getObject();
		if (obj instanceof CodeUnit) {
			ListingModel layoutModel = proxy.getListingLayoutModel();
			Program program = layoutModel.getProgram();
			return new EntropyFieldLocation(program, ((CodeUnit) obj).getAddress(), col);
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {
		if (programLoc instanceof EntropyFieldLocation) {
			return new FieldLocation(index, fieldNum, 0,
				((EntropyFieldLocation) programLoc).getCharOffset());
		}
		return null;
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel myModel, HighlightProvider myHlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		return new EntropyFieldFactory(myModel, myHlProvider, displayOptions, fieldOptions);
	}

}
