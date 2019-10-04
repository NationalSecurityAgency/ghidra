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

import java.beans.PropertyEditor;
import java.math.BigInteger;
import java.util.*;

import javax.swing.Icon;
import javax.swing.event.ChangeListener;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.app.util.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;
import resources.MultiIcon;
import resources.ResourceManager;
import resources.icons.EmptyIcon;
import resources.icons.TranslateIcon;

/**
 *  Generates label Fields.
 */
public class LabelFieldFactory extends FieldFactory {

	private final static int MAX_OFFCUT_DISPLAY = 30; // arbitrary

	public final static String FIELD_NAME = "Label";
	public final static String OFFCUT_STYLE = "XRef Offcut Style";
	public final static String GROUP_TITLE = "Labels Field";
	public final static String DISPLAY_FUNCTION_LABEL =
		GROUP_TITLE + Options.DELIMITER + "Display Function Label";
	private final static String NAMESPACE_OPTIONS =
		GROUP_TITLE + Options.DELIMITER + "Display Namespace";

	// These icons would normally be static, but can't be because the class searcher loads this
	// class and it triggers swing access which is not allowed in headless.
	private Icon EMPTY_ICON = new EmptyIcon(12, 16);
	private Icon ANCHOR_ICON = new MultiIcon(EMPTY_ICON,
		new TranslateIcon(ResourceManager.loadImage("images/pin.png"), 0, 4));

	private PropertyEditor namespaceOptionsEditor = new NamespacePropertyEditor();

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
		initIcons();
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private LabelFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

		inspector = new SymbolInspector(displayOptions, null);

		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "Labels_Field");
		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(hl);
		fieldOptions.registerOption(DISPLAY_FUNCTION_LABEL, true, hl,
			"Shows function names in a label field below the function header");

		displayFunctionLabel = fieldOptions.getBoolean(DISPLAY_FUNCTION_LABEL, true);

		setupNamespaceOptions(fieldOptions);

		// Create code unit format and associated options - listen for changes
		codeUnitFormat = new LabelCodeUnitFormat(fieldOptions);
		codeUnitFormat.addChangeListener(codeUnitFormatListener);
		initIcons();
	}

	private void initIcons() {
		EMPTY_ICON = new EmptyIcon(12, 16);
		ANCHOR_ICON = new MultiIcon(EMPTY_ICON,
			new TranslateIcon(ResourceManager.loadImage("images/pin.png"), 0, 4));

	}

	private void setupNamespaceOptions(Options fieldOptions) {
		// we need to install a custom editor that allows us to edit a group of related options
		fieldOptions.registerOption(NAMESPACE_OPTIONS, OptionType.CUSTOM_TYPE,
			new NamespaceWrappedOption(), null, "Adjusts the Label Field namespace display",
			namespaceOptionsEditor);
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
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getField(ProxyObj, int)
	 */
	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		int x = startX + varWidth;
		CodeUnit cu = (CodeUnit) obj;

		Address currAddr = cu.getMinAddress();

		Program prog = cu.getProgram();
		inspector.setProgram(prog);

		Listing list = prog.getListing();
		Function func = list.getFunctionAt(currAddr);

		Symbol[] symbols = cu.getSymbols();

		// check to see if there is an offcut reference to this code unit
		// if there is, then create a "OFF" label
		//
		List<Address> offcuts = getOffcutReferenceAddress(cu);
		boolean hasOffcuts = offcuts.size() > 0;

		// if there is only a function symbol and we are not showing function symbols, get out.
		if (!hasOffcuts && symbols.length == 1 && func != null && !displayFunctionLabel) {
			return null;
		}

		makePrimaryLastItem(symbols);

		int length = symbols.length;
		if (!displayFunctionLabel && func != null) {
			length = symbols.length - 1;
		}

		if (hasOffcuts) {
			length += offcuts.size();
		}

		if (length == 0) {
			return null;
		}

		FieldElement[] textElements = new FieldElement[length];
		int nextPos = 0;

		if (hasOffcuts) {
			for (int i = 0; i < offcuts.size(); i++) {
				AttributedString as = getAttributedOffsetText(obj, cu, currAddr, offcuts.get(i));
				if (as == null) {
					as = new AttributedString(EMPTY_ICON,
						SymbolUtilities.getDynamicOffcutName(currAddr),
						inspector.getOffcutSymbolColor(),
						getMetrics(inspector.getOffcutSymbolStyle()), false, null);
				}
				textElements[nextPos++] = new TextFieldElement(as, nextPos, 0);
			}
		}

		for (Symbol symbol : symbols) {
			if (func != null && symbol.isPrimary() && !displayFunctionLabel) {
				continue;
			}

			Icon icon = symbol.isPinned() ? ANCHOR_ICON : EMPTY_ICON;
			ColorAndStyle c = inspector.getColorAndStyle(symbol);
			AttributedString as = new AttributedString(icon, checkLabelString(symbol, prog),
				c.getColor(), getMetrics(c.getStyle()), false, null);
			textElements[nextPos++] = new TextFieldElement(as, nextPos, 0);
		}

		return ListingTextField.createMultilineTextField(this, proxy, textElements, x, width,
			Integer.MAX_VALUE, hlProvider);
	}

	private String getOffsetText(CodeUnit cu, Address currAddr, Address offcutAddress) {

		SymbolTable symbolTable = cu.getProgram().getSymbolTable();
		Symbol offcutSymbol = symbolTable.getPrimarySymbol(offcutAddress);
		if (offcutSymbol == null) {
			// While we should always have a primary symbol to a referenced
			// address - invalid data could cause this rule to be violated,
			// so lets play nice and return something
			return SymbolUtilities.getDynamicOffcutName(offcutAddress);
		}

		String offcutSymbolText = null;
		if (!offcutSymbol.isDynamic()) {
			// the formatter doesn't change dynamic labels
			offcutSymbolText = codeUnitFormat.getOffcutLabelString(offcutAddress, cu);
		}
		else {
			offcutSymbolText = offcutSymbol.getName();
		}

		return offcutSymbolText;
	}

	private AttributedString getAttributedOffsetText(Object obj, CodeUnit cu, Address currAddr,
			Address offcutAddress) {

		return new AttributedString(EMPTY_ICON, getOffsetText(cu, currAddr, offcutAddress),
			inspector.getOffcutSymbolColor(), getMetrics(inspector.getOffcutSymbolStyle()), false,
			null);
	}

	private String checkLabelString(Symbol symbol, Program program) {

		if (!displayLocalNamespace && !displayNonLocalNamespace) {
			return symbol.getName(); // no namespaces being shown
		}

		Namespace addressNamespace = program.getSymbolTable().getNamespace(symbol.getAddress());
		Namespace symbolNamespace = symbol.getParentNamespace();
		boolean isLocal = symbolNamespace.equals(addressNamespace);
		if (!isLocal) {
			return symbol.getName(displayNonLocalNamespace);
		}

		// O.K., we ARE a local namespace, how to display it?
		if (!displayLocalNamespace) {
			return symbol.getName();
		}

		// use the namespace name or a custom, user-defined value
		if (useLocalPrefixOverride) {
			return localPrefixText + symbol.getName(false);
		}
		return symbol.getName(true);

	}

	private List<Address> getOffcutReferenceAddress(CodeUnit cu) {

		Program prog = cu.getProgram();
		if (cu.getLength() == 1) {
			return Collections.emptyList();
		}
		Address nextAddr = cu.getMinAddress().next();
		if (nextAddr == null) {
			return Collections.emptyList();
		}

		Address endAddress = cu.getMaxAddress();

		List<Address> list = new ArrayList<>();
		AddressIterator it =
			prog.getReferenceManager().getReferenceDestinationIterator(nextAddr, true);
		while (it.hasNext()) {
			Address addr = it.next();
			if (addr.compareTo(endAddress) > 0) {
				break;
			}

// TODO: check for wrapping - temporary work-around
			if (addr.compareTo(cu.getMinAddress()) > 0) {
				list.remove(addr);
				list.add(addr);
				if (list.size() > MAX_OFFCUT_DISPLAY) {
					return list; // short-circuit
				}
			}
		}

		SymbolIterator symIter = prog.getSymbolTable().getSymbolIterator(nextAddr, true);
		while (symIter.hasNext()) {
			Symbol s = symIter.next();
			Address addr = s.getAddress();
			if (addr.compareTo(endAddress) > 0) {
				break;
			}

// TODO: check for wrapping - temporary work-around
			if (addr.compareTo(cu.getMinAddress()) > 0) {
				list.remove(addr);
				list.add(addr);
				if (list.size() > MAX_OFFCUT_DISPLAY) {
					return list; // short-circuit
				}
			}
		}

		return list;
	}

	/**
	 * Move primary symbol to last element in array ...
	 */
	private void makePrimaryLastItem(Symbol[] symbols) {
		for (int i = 0; i < symbols.length - 1; ++i) {
			if (symbols[i].isPrimary()) {
				Symbol primary = symbols[i];
				System.arraycopy(symbols, i + 1, symbols, i, symbols.length - i - 1);
				symbols[symbols.length - 1] = primary;

				break;
			}
		}
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

		List<Address> offcuts = getOffcutReferenceAddress(cu);

		// fictitious offcut labels are listed first, check if row is a fictitious offcut label
		if (row < offcuts.size()) {
			return getLocationForOffcuttLabel(row, col, cu, cpath, offcuts);
		}

		int symbolIndex = row - offcuts.size();

		Symbol s = getCodeOrFunctionSymbol(cu, symbolIndex);
		if (s == null) {
			return new CodeUnitLocation(cu.getProgram(), cu.getMinAddress(), cpath, 0, 0, 0);
		}
		return new LabelFieldLocation(s, row, col);
	}

	private Symbol getCodeOrFunctionSymbol(CodeUnit cu, int symbolIndex) {
		Symbol[] symbols = cu.getSymbols();
		if (symbols.length == 0) {
			return null;
		}

		makePrimaryLastItem(symbols);

		if (symbolIndex >= symbols.length) {
			symbolIndex = symbols.length - 1;
		}
		Symbol symbol = symbols[symbolIndex];
		SymbolType symbolType = symbol.getSymbolType();
		if (symbolType != SymbolType.LABEL && symbolType != SymbolType.FUNCTION) {
			return null;
		}
		return symbol;
	}

	private ProgramLocation getLocationForOffcuttLabel(int row, int col, CodeUnit cu, int[] cpath,
			List<Address> offcuts) {
		Address addr = cu.getMinAddress();
		String text = getOffsetText(cu, addr, offcuts.get(row));
		if (text == null) {
			text = SymbolUtilities.getDynamicOffcutName(addr);
		}
		// since these labels are fictitious, they don't have a namespace.
		return new LabelFieldLocation(cu.getProgram(), addr, cpath, text, null, row, col);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		Object obj = bf.getProxy().getObject();
		if (!(programLoc instanceof LabelFieldLocation)) {
			return null;
		}
		LabelFieldLocation loc = (LabelFieldLocation) programLoc;

		if (!(obj instanceof CodeUnit)) {
			return null;
		}

		String lableName = loc.getName();

		CodeUnit cu = (CodeUnit) obj;

		List<Address> offcuts = getOffcutReferenceAddress(cu);
		for (int i = 0; i < offcuts.size(); i++) {
			String text = getOffsetText(cu, cu.getMinAddress(), offcuts.get(i));
			if (text != null && text.equals(lableName)) {
				return new FieldLocation(index, fieldNum, i, loc.getCharOffset());
			}
		}

		Symbol[] symbols = cu.getSymbols();
		makePrimaryLastItem(symbols);
		if (symbols.length == 0) {
			return null;
		}

		for (int i = 0; i < symbols.length; i++) {
			if (symbols[i].getName().equals(lableName)) {
				return new FieldLocation(index, fieldNum, i + offcuts.size(), loc.getCharOffset());
			}
		}
		return null;
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
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider provider,
			ToolOptions pDisplayOptions, ToolOptions fieldOptions) {
		return new LabelFieldFactory(formatModel, provider, pDisplayOptions, fieldOptions);
	}

}
