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
package ghidra.app.util.disassemble;

import java.awt.Color;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.util.ProgramLocation;
import ghidra.util.classfinder.ClassSearcher;

public class ExternalDisassemblyFieldFactory extends FieldFactory {

	private static List<ExternalDisassembler> availableDisassemblers;

	private static synchronized List<ExternalDisassembler> getAvailableDisassemblers() {
		if (availableDisassemblers != null) {
			return availableDisassemblers;
		}
		availableDisassemblers = new ArrayList<>();

		// find the available external disassemblers
		List<ExternalDisassembler> extDisassemblers =
			ClassSearcher.getInstances(ExternalDisassembler.class);

		for (ExternalDisassembler disassember : extDisassemblers) {
			availableDisassemblers.add(disassember);
		}
		return availableDisassemblers;
	}

	public static final String FIELD_NAME = "External Disassembly";

	public ExternalDisassemblyFieldFactory() {
		super(FIELD_NAME);
	}

	private ExternalDisassemblyFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		// have no options
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {
		if (loc instanceof ExternalDisassemblyFieldLocation) {
			return new FieldLocation(index, fieldNum,
				((ExternalDisassemblyFieldLocation) loc).getRow(),
				((ExternalDisassemblyFieldLocation) loc).getCharOffset());
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		ProxyObj<?> proxy = bf.getProxy();
		Object obj = proxy.getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		return new ExternalDisassemblyFieldLocation(cu.getProgram(), cu.getMinAddress(), row, col);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel,
			HighlightProvider highlightProvider, ToolOptions options, ToolOptions fieldOptions) {
		return new ExternalDisassemblyFieldFactory(formatModel, highlightProvider, options,
			fieldOptions);
	}

	private ExternalDisassembler getDisassembler(Language language) {
		for (ExternalDisassembler disassembler : getAvailableDisassemblers()) {
			if (disassembler.isSupportedLanguage(language)) {
				return disassembler;
			}
		}
		return null;
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		if (!enabled) {
			return null;
		}
		Object obj = proxy.getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;

		try {
			String disassembly = getDisassemblyText(cu);
			if (disassembly == null) {
				return null;
			}
			AttributedString text = new AttributedString(disassembly, Color.black, getMetrics());
			FieldElement fieldElement = new TextFieldElement(text, 0, 0);
			return ListingTextField.createSingleLineTextField(this, proxy, fieldElement,
				startX + varWidth, width, hlProvider);
		}
		catch (Exception e) {
			return getErrorText(proxy, varWidth, e);
		}
	}

	private String getDisassemblyText(CodeUnit cu) throws Exception {
		Language language = cu.getProgram().getLanguage();
		ExternalDisassembler disassembler = getDisassembler(language);
		if (disassembler == null) {
			return null;
		}
		String disassembly = disassembler.getDisassembly(cu);
		if (disassembly == null) {
			return null;
		}
		String prefix = disassembler.getDisassemblyDisplayPrefix(cu);
		if (prefix != null) {
			disassembly = prefix + " " + disassembly;
		}
		return disassembly;
	}

	private ListingTextField getErrorText(ProxyObj<?> proxy, int varWidth, Exception e) {
		String message = e.getMessage();
		if (message == null) {
			message = e.toString();
		}
		AttributedString errorText = new AttributedString(message, Color.red, getMetrics());
		FieldElement fieldElement = new TextFieldElement(errorText, 0, 0);
		return ListingTextField.createSingleLineTextField(this, proxy, fieldElement,
			startX + varWidth, width, hlProvider);
	}
}
