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
import java.awt.FontMetrics;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.event.ChangeListener;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GIcon;
import ghidra.app.util.*;
import ghidra.app.util.viewer.field.LabelFieldSymbolLoader.Symbols;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;
import resources.MultiIcon;
import resources.icons.EmptyIcon;

/**
 *  Generates label Fields.
 */
public class LabelFieldFactory extends FieldFactory {

	public final static String FIELD_NAME = "Label";
	public final static String OFFCUT_STYLE = "XRef Offcut Style";
	public final static String GROUP_TITLE = "Labels Field";
	public final static String DISPLAY_FUNCTION_LABEL =
		GROUP_TITLE + Options.DELIMITER + "Display Function Label";
	private final static String NAMESPACE_OPTIONS =
		GROUP_TITLE + Options.DELIMITER + "Display Namespace";

	private static final String MAX_LABELS_LABEL =
		GROUP_TITLE + Options.DELIMITER + "Maximum Number of Labels to Display";

	private static final int MAX_LABELS = 10;
	private int maxLabels = MAX_LABELS;

	// These icons would normally be static, but can't be because the class searcher loads this
	// class and it triggers swing access which is not allowed in headless.
	private Icon EMPTY_ICON = new EmptyIcon(12, 16);
	private Icon ANCHOR_ICON =
		new MultiIcon(EMPTY_ICON, new GIcon("icon.base.util.viewer.fieldfactory.label"));

	private boolean displayFunctionLabel;
	private boolean displayLocalNamespace;
	private boolean displayNonLocalNamespace;
	private SymbolInspector inspector;
	private boolean useLocalPrefixOverride;
	private String localPrefixText;

	protected BrowserCodeUnitFormat codeUnitFormat;
	private ChangeListener codeUnitFormatListener = e -> LabelFieldFactory.this.model.update();

	public LabelFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private LabelFieldFactory(FieldFormatModel model, ListingHighlightProvider hlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

		inspector = new SymbolInspector(displayOptions, null);

		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "Labels_Field");
		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(hl);
		fieldOptions.registerOption(DISPLAY_FUNCTION_LABEL, true, hl,
			"Shows function names in a label field below the function header");

		fieldOptions.registerOption(MAX_LABELS_LABEL, MAX_LABELS, hl,
			"Sets the maximum number of labels to display.");

		displayFunctionLabel = fieldOptions.getBoolean(DISPLAY_FUNCTION_LABEL, true);

		setupNamespaceOptions(fieldOptions);

		maxLabels = fieldOptions.getInt(MAX_LABELS_LABEL, MAX_LABELS);

		// Create code unit format and associated options - listen for changes
		codeUnitFormat = new LabelCodeUnitFormat(fieldOptions);
		codeUnitFormat.addChangeListener(codeUnitFormatListener);
	}

	private void setupNamespaceOptions(Options fieldOptions) {
		// we need to install a custom editor that allows us to edit a group of related options
		fieldOptions.registerOption(NAMESPACE_OPTIONS, OptionType.CUSTOM_TYPE,
			new NamespaceWrappedOption(), null, "Adjusts the Label Field namespace display",
			() -> new NamespacePropertyEditor());
		CustomOption wrappedOption =
			fieldOptions.getCustomOption(NAMESPACE_OPTIONS, new NamespaceWrappedOption());
		if (!(wrappedOption instanceof NamespaceWrappedOption)) {
			throw new AssertException(
				"Someone set an option for " + NAMESPACE_OPTIONS + " that is not the expected " +
					"ghidra.app.util.viewer.field.NamespaceWrappedOption type.");
		}

		NamespaceWrappedOption namespaceOption = (NamespaceWrappedOption) wrappedOption;
		displayLocalNamespace = namespaceOption.isShowLocalNamespace();
		displayNonLocalNamespace = namespaceOption.isShowNonLocalNamespace();
		useLocalPrefixOverride = namespaceOption.isUseLocalPrefixOverride();
		localPrefixText = namespaceOption.getLocalPrefixText();
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(DISPLAY_FUNCTION_LABEL)) {
			displayFunctionLabel = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(NAMESPACE_OPTIONS)) {
			setupNamespaceOptions(options);
			model.update();
		}
		else if (optionName.equals(MAX_LABELS_LABEL)) {
			setMaxSize(((Integer) newValue).intValue(), options);
			model.update();
		}
	}

	private void setMaxSize(int n, Options options) {
		if (n < 1) {
			n = 1;
			options.setInt(MAX_LABELS_LABEL, 1);
		}
		maxLabels = n;
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;
		LabelFieldSymbolLoader loader =
			new LabelFieldSymbolLoader(cu, maxLabels, displayFunctionLabel);
		Symbols symbols = loader.getSymbols();

		int total = symbols.size();
		if (total == 0) {
			return null;
		}

		Address addr = cu.getMinAddress();
		Program program = cu.getProgram();

		int x = startX + varWidth;
		if (total == 1 && addr.isExternalAddress()) {
			Symbol s = symbols.get(0);
			TextFieldElement externalField = createExternalField(program, s);
			if (externalField != null) {
				return ListingTextField.createMultilineTextField(this, proxy,
					List.of(externalField), x, width, hlProvider);
			}
		}

		List<FieldElement> elements = new ArrayList<>();

		List<Symbol> offcuts = symbols.getOffcuts();
		createOffcutElements(obj, cu, addr, offcuts, elements);

		// grab the remaining non-offcut symbols
		for (int i = offcuts.size(); i < symbols.size(); i++) {
			Symbol s = symbols.get(i);
			AttributedString as = createSymbolString(s);
			elements.add(new TextFieldElement(as, elements.size(), 0));
		}

		if (loader.hasMore()) {
			Symbol nonPrimarySymbol = symbols.get(0);
			int lastRow = elements.size();
			AttributedString as = createMoreSymbolsString(nonPrimarySymbol);

			// place this above primary symbol, as that seems to look the best
			int primaryIndex = elements.size() - 1;
			int index = primaryIndex;
			elements.add(index, new TextFieldElement(as, lastRow, 0));
		}

		return ListingTextField.createMultilineTextField(this, proxy, elements, x, width,
			hlProvider);
	}

	private AttributedString createSymbolString(Symbol s) {
		Icon icon = s.isPinned() ? ANCHOR_ICON : EMPTY_ICON;
		ColorAndStyle c = inspector.getColorAndStyle(s);
		FontMetrics fm = getMetrics(c.getStyle());
		Color color = c.getColor();
		String text = getLabelString(s);
		return new AttributedString(icon, text, color, fm, false, null);
	}

	private AttributedString createMoreSymbolsString(Symbol prototype) {
		ColorAndStyle c = inspector.getColorAndStyle(prototype);
		FontMetrics fm = getMetrics(c.getStyle());
		Color color = c.getColor();
		String text = MoreLabelFieldLocation.MORE_LABELS_STRING;
		return new AttributedString(EMPTY_ICON, text, color, fm, false, null);
	}

	private void createOffcutElements(Object obj, CodeUnit cu, Address addr, List<Symbol> offcuts,
			List<FieldElement> elements) {

		FontMetrics fm = getMetrics(inspector.getOffcutSymbolStyle());
		Color color = inspector.getOffcutSymbolColor();
		for (Symbol s : offcuts) {

			Address offcut = s.getAddress();
			String text = getOffcutText(cu, addr, offcut, s);
			if (text == null) {
				text = SymbolUtilities.getDynamicOffcutName(addr);
			}

			AttributedString as = new AttributedString(EMPTY_ICON, text, color, fm, false, null);
			elements.add(new TextFieldElement(as, elements.size(), 0));
		}
	}

	private TextFieldElement createExternalField(Program p, Symbol symbol) {

		// Show external address and original imported name (not supported by field location)
		ExternalLocation extLoc = p.getExternalManager().getExternalLocation(symbol);
		if (extLoc == null) {
			return null;
		}

		StringBuilder externalLocationDetails = new StringBuilder();
		Address addr = extLoc.getAddress();
		if (addr != null) {
			externalLocationDetails.append(addr.toString());
		}
		String origImportedName = extLoc.getOriginalImportedName();
		if (origImportedName != null) {
			if (!externalLocationDetails.isEmpty()) {
				externalLocationDetails.append(": ");
			}
			externalLocationDetails.append(origImportedName);
		}

		if (externalLocationDetails.isEmpty()) {
			return null;
		}

		FontMetrics fm = getMetrics(OptionsGui.LABELS_NON_PRIMARY.getStyle());
		String text = externalLocationDetails.toString();
		Color color = OptionsGui.LABELS_NON_PRIMARY.getColor();
		AttributedString as = new AttributedString(EMPTY_ICON, text, color, fm, false, null);
		return new TextFieldElement(as, 0, 0);
	}

	private String getOffcutText(CodeUnit cu, Address currAddr, Address offcutAddress,
			Symbol symbol) {

		if (symbol == null) {
			// While we should always have a primary symbol to a referenced
			// address - invalid data could cause this rule to be violated,
			// so lets play nice and return something
			return SymbolUtilities.getDynamicOffcutName(offcutAddress);
		}

		String offcutSymbolText = null;
		if (!symbol.isDynamic()) {
			// the formatter doesn't change dynamic labels
			offcutSymbolText = codeUnitFormat.getOffcutLabelString(offcutAddress, cu, null, symbol);
		}
		else {
			offcutSymbolText = symbol.getName();
		}

		return offcutSymbolText;
	}

	private String getLabelString(Symbol symbol) {

		if (!displayLocalNamespace && !displayNonLocalNamespace) {
			return simplifyTemplates(symbol.getName()); // no namespaces being shown
		}

		Program program = symbol.getProgram();
		Namespace addressNamespace = program.getSymbolTable().getNamespace(symbol.getAddress());
		Namespace symbolNamespace = symbol.getParentNamespace();
		boolean isLocal = symbolNamespace.equals(addressNamespace);
		if (!isLocal) {
			return simplifyTemplates(symbol.getName(displayNonLocalNamespace));
		}

		// O.K., we ARE a local namespace, how to display it?
		if (!displayLocalNamespace) {
			return simplifyTemplates(symbol.getName());
		}

		// use the namespace name or a custom, user-defined value
		if (useLocalPrefixOverride) {
			return simplifyTemplates(localPrefixText + symbol.getName(false));
		}
		return simplifyTemplates(symbol.getName(true));
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit cu)) {
			return null;
		}

		LabelFieldSymbolLoader loader =
			new LabelFieldSymbolLoader(cu, maxLabels, displayFunctionLabel);

		MoreLabelFieldLocation moreLocation = createMoreLocation(cu, loader, row, col);
		if (moreLocation != null) {
			return moreLocation;
		}

		// If we have more, then the [more] row is added to the display, which pushes the last
		// row down 1.
		int symbolRow = row;
		if (row >= maxLabels) {
			symbolRow = row - 1;
		}

		Symbols symbols = loader.getSymbols();
		Symbol s = symbols.get(symbolRow);
		return new LabelFieldLocation(s, symbolRow, col);
	}

	private MoreLabelFieldLocation createMoreLocation(CodeUnit cu, LabelFieldSymbolLoader loader,
			int row, int col) {

		if (!loader.hasMore()) {
			return null;
		}

		int moreRow = maxLabels - 1; // the [more] text is just above the last, primary symbol
		if (row != moreRow) {
			return null;
		}

		Program p = cu.getProgram();
		Address addr = cu.getMinAddress();
		return new MoreLabelFieldLocation(p, addr, moreRow, col);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation location) {

		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit cu)) {
			return null;
		}

		if (!(location instanceof LabelFieldLocation) &&
			!(location instanceof MoreLabelFieldLocation)) {
			return null;
		}

		/*
		 	Handle the case where we have 2 tools with a different number of rows showing.
		 		1) if the given location is a [more] location, then use the [more] field.    		 
		 		2) If the given row is the primary symbol's row, then use that.  		 		
		 		3) What's left is all rows above the [more].  
		 */

		LabelFieldSymbolLoader loader =
			new LabelFieldSymbolLoader(cu, maxLabels, displayFunctionLabel);
		if (loader.hasMore() && location instanceof MoreLabelFieldLocation moreLoc) {
			// we have [more] showing and the location is a [more] location
			int row = maxLabels - 1; // my more row
			int col = moreLoc.getCharOffset();
			return new FieldLocation(index, fieldNum, row, col);
		}

		LabelFieldLocation labelLocation = (LabelFieldLocation) location;
		Symbol symbol = labelLocation.getSymbol();
		Symbols symbols = loader.getSymbols();
		if (symbol != null && symbol.isPrimary()) {
			int row = loader.hasMore() ? symbols.size() : symbols.size() - 1;
			return new FieldLocation(index, fieldNum, row, labelLocation.getCharOffset());
		}

		int symbolRow = labelLocation.getRow();
		symbolRow = Math.min(symbolRow, maxLabels - 1);

		// We already handle the primary case and the case when we have a more location.  For all 
		// other locations, just use the given row, capping at our max display.
		return new FieldLocation(index, fieldNum, symbolRow, labelLocation.getCharOffset());
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}
		return (category == FieldFormatModel.INSTRUCTION_OR_DATA ||
			category == FieldFormatModel.OPEN_DATA);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, ListingHighlightProvider provider,
			ToolOptions pDisplayOptions, ToolOptions fieldOptions) {
		return new LabelFieldFactory(formatModel, provider, pDisplayOptions, fieldOptions);
	}

}
