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
import java.beans.PropertyEditor;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Comparator;

import javax.swing.event.ChangeListener;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.RowColLocation;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.XReferenceUtil;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.XRefFieldLocation;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

/**
 * Cross-reference Field Factory
 */
public class XRefFieldFactory extends FieldFactory {
	static final String MORE_XREFS_STRING = "[more]";
	public static final String FIELD_NAME = "XRef";
	private static final String DELIMITER = ", ";
	private static final int MAX_XREFS = 20;

	public static enum SORT_CHOICE {
		Address, Type
	}

	protected SORT_CHOICE sortChoice = SORT_CHOICE.Address;

	private static final String GROUP_TITLE = "XREFs Field";
	private static final String DELIMITER_MSG = GROUP_TITLE + Options.DELIMITER + "Delimiter";
	private static final String MAX_XREFS_MSG =
		GROUP_TITLE + Options.DELIMITER + "Maximum Number of XREFs to Display";
	private static final String DISPLAY_BLOCK_NAME_MSG =
		GROUP_TITLE + Options.DELIMITER + "Display Local Block";
	private static final String SORT_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Sort References By";
	private static final String DISPLAY_REFERENCE_TYPE_MSG =
		GROUP_TITLE + Options.DELIMITER + "Display Reference Type";
	private final static String NAMESPACE_OPTIONS =
		GROUP_TITLE + Options.DELIMITER + "Display Namespace";

	private PropertyEditor namespaceOptionsEditor = new NamespacePropertyEditor();

	protected Color offcutColor;
	protected Color readColor;
	protected Color writeColor;
	protected Color otherColor;
	protected String delim = DELIMITER;
	protected boolean displayBlockName;

	protected int maxXRefs = MAX_XREFS;
	protected boolean displayRefType = true;
	protected Comparator<Reference> typeComparator;
	protected boolean displayLocalNamespace;
	protected boolean displayNonLocalNamespace;
	protected boolean useLocalPrefixOverride;
	protected String localPrefixText;

	private BrowserCodeUnitFormat codeUnitFormat;
	private ChangeListener codeUnitFormatListener = e -> XRefFieldFactory.this.model.update();

	/**
	 * Constructor
	 */
	public XRefFieldFactory() {
		this(FIELD_NAME);
	}

	protected XRefFieldFactory(String name) {
		super(name);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	public XRefFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, ToolOptions fieldOptions) {
		this(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

	}

	/**
	 * Constructs a new XRefFieldFactory based on the provider and model.
	 *
	 * @param name the owner of this field factory
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	protected XRefFieldFactory(String name, FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, ToolOptions fieldOptions) {
		super(name, model, hlProvider, displayOptions, fieldOptions);

		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "XREFs_Field");
		fieldOptions.registerOption(DELIMITER_MSG, DELIMITER, hl,
			"Delimiter string used for separating multiple xrefs.");
		fieldOptions.registerOption(DISPLAY_BLOCK_NAME_MSG, false, hl,
			"Prepends xref addresses with the " +
				"name of the memory block containing the xref address.");
		fieldOptions.registerOption(MAX_XREFS_MSG, MAX_XREFS, hl,
			"Sets the maximum number of xrefs to display.");
		fieldOptions.registerOption(DISPLAY_REFERENCE_TYPE_MSG, true, hl, "Appends xref type.");
		fieldOptions.registerOption(SORT_OPTION, SORT_CHOICE.Address, hl, "How to sort the xrefs");

		offcutColor = displayOptions.getColor(OptionsGui.XREF_OFFCUT.getColorOptionName(),
			OptionsGui.XREF_OFFCUT.getDefaultColor());
		readColor = displayOptions.getColor(OptionsGui.XREF_READ.getColorOptionName(),
			OptionsGui.XREF_READ.getDefaultColor());
		writeColor = displayOptions.getColor(OptionsGui.XREF_WRITE.getColorOptionName(),
			OptionsGui.XREF_WRITE.getDefaultColor());
		otherColor = displayOptions.getColor(OptionsGui.XREF_OTHER.getColorOptionName(),
			OptionsGui.XREF_OTHER.getDefaultColor());

		typeComparator = (r1, r2) -> {
			if (r1.getReferenceType().toString().equals(r2.getReferenceType().toString())) {
				return r1.compareTo(r2);
			}
			return r1.getReferenceType().toString().compareTo(r2.getReferenceType().toString());
		};

		delim = fieldOptions.getString(DELIMITER_MSG, DELIMITER);
		displayBlockName = fieldOptions.getBoolean(DISPLAY_BLOCK_NAME_MSG, false);

		maxXRefs = fieldOptions.getInt(MAX_XREFS_MSG, MAX_XREFS);
		sortChoice = fieldOptions.getEnum(SORT_OPTION, SORT_CHOICE.Address);
		displayRefType = fieldOptions.getBoolean(DISPLAY_REFERENCE_TYPE_MSG, true);

		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(hl);

		setupNamespaceOptions(fieldOptions);

		// Create code unit format and associated options - listen for changes
		codeUnitFormat = new BrowserCodeUnitFormat(fieldOptions, true);
		codeUnitFormat.addChangeListener(codeUnitFormatListener);
	}

	private void setupNamespaceOptions(Options fieldOptions) {
		// we need to install a custom editor that allows us to edit a group of related options
		fieldOptions.registerOption(NAMESPACE_OPTIONS, OptionType.CUSTOM_TYPE,
			new NamespaceWrappedOption(), null, "Adjusts the XREFs Field namespace display",
			namespaceOptionsEditor);
		CustomOption customOption = fieldOptions.getCustomOption(NAMESPACE_OPTIONS, null);
		fieldOptions.getOptions(NAMESPACE_OPTIONS).setOptionsHelpLocation(
			new HelpLocation("CodeBrowserPlugin", "XREFs_Field"));
		if (!(customOption instanceof NamespaceWrappedOption)) {
			throw new AssertException(
				"Someone set an option for " + NAMESPACE_OPTIONS + " that is not the expected " +
					"ghidra.app.util.viewer.field.NamespaceWrappedOption type.");
		}

		NamespaceWrappedOption namespaceOption = (NamespaceWrappedOption) customOption;
		displayLocalNamespace = namespaceOption.isShowLocalNamespace();
		displayNonLocalNamespace = namespaceOption.isShowNonLocalNamespace();
		useLocalPrefixOverride = namespaceOption.isUseLocalPrefixOverride();
		localPrefixText = namespaceOption.getLocalPrefixText();
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.displayOptionsChanged(options, optionName, oldValue, newValue);

		if (optionName.equals(OptionsGui.XREF_OFFCUT.getColorOptionName())) {
			offcutColor = (Color) newValue;
			model.update();
		}
		else if (optionName.equals(OptionsGui.XREF.getColorOptionName())) {
			color = (Color) newValue;
			model.update();
		}
		else if (optionName.equals(OptionsGui.XREF_READ.getColorOptionName())) {
			readColor = (Color) newValue;
			model.update();
		}
		else if (optionName.equals(OptionsGui.XREF_WRITE.getColorOptionName())) {
			writeColor = (Color) newValue;
			model.update();
		}
		else if (optionName.equals(OptionsGui.XREF_OTHER.getColorOptionName())) {
			otherColor = (Color) newValue;
			model.update();
		}
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.fieldOptionsChanged(options, optionName, oldValue, newValue);
		if (optionName.equals(DELIMITER_MSG)) {
			delim = (String) newValue;
			model.update();
		}
		else if (optionName.equals(DISPLAY_BLOCK_NAME_MSG)) {
			displayBlockName = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(DISPLAY_REFERENCE_TYPE_MSG)) {
			displayRefType = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(MAX_XREFS_MSG)) {
			setMaxSize(((Integer) newValue).intValue(), options);
		}
		else if (optionName.equals(SORT_OPTION)) {
			sortChoice = (SORT_CHOICE) newValue;
			model.update();
		}
		else if (optionName.equals(NAMESPACE_OPTIONS)) {
			setupNamespaceOptions(options);
			model.update();
		}
	}

	private void setMaxSize(int n, Options options) {
		if (n < 1) {
			n = 1;
			options.setInt(MAX_XREFS_MSG, 1);
		}
		maxXRefs = n;
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.XREF.getDefaultColor();
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled) {
			return null;
		}

		if (obj == null || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		Program pgm = cu.getProgram();

		Reference[] xrefs = XReferenceUtil.getXReferences(cu, maxXRefs + 1);

		int maxOffcuts = Math.max(0, maxXRefs - xrefs.length);
		Reference[] offcuts = XReferenceUtil.getOffcutXReferences(cu, maxOffcuts);
		if (sortChoice == SORT_CHOICE.Address) {
			Arrays.sort(xrefs);
			Arrays.sort(offcuts);
		}
		else {
			Arrays.sort(xrefs, typeComparator);
			Arrays.sort(offcuts, typeComparator);
		}
		int totalXrefs = xrefs.length + offcuts.length;
		if (totalXrefs == 0) {
			return null;
		}

		boolean tooMany = totalXrefs > maxXRefs;

		AttributedString delimiter = new AttributedString(delim, Color.BLACK, getMetrics());
		FieldElement[] elements = new FieldElement[tooMany ? maxXRefs + 1 : totalXrefs];
		Function currentFunction =
			pgm.getFunctionManager().getFunctionContaining(cu.getMinAddress());
		int count = 0;
		for (; count < xrefs.length && count < elements.length; count++) {
			String prefix = getPrefix(pgm, xrefs[count], currentFunction);
			String addressString = xrefs[count].getFromAddress().toString(prefix);
			AttributedString as = new AttributedString(addressString, color, getMetrics());
			if (displayRefType) {
				as = createRefTypeAttributedString(xrefs[count], as);
			}
			if (count < totalXrefs - 1) {
				as = new CompositeAttributedString(new AttributedString[] { as, delimiter });
			}
			else {
				// This added to prevent a situation where resizing field to a particular size,
				// resulted in layout of references to be strange
				char[] charSpaces = new char[delimiter.length()];
				Arrays.fill(charSpaces, ' ');
				AttributedString spaces =
					new AttributedString(new String(charSpaces), color, getMetrics());
				as = new CompositeAttributedString(new AttributedString[] { as, spaces });
			}
			elements[count] = new TextFieldElement(as, count, 0);
		}

		for (int i = 0; i < offcuts.length && count < elements.length; i++, count++) {
			String prefix = getPrefix(pgm, offcuts[i], currentFunction);
			String addressString = offcuts[i].getFromAddress().toString(prefix);
			AttributedString as = new AttributedString(addressString, offcutColor, getMetrics());
			if (displayRefType) {
				as = createRefTypeAttributedString(offcuts[i], as);
			}
			if (count < totalXrefs - 1) {
				as = new CompositeAttributedString(new AttributedString[] { as, delimiter });
			}
			else {
				// This added to prevent a situation where resizing field to a particular size,
				// resulted in layout of references to be strange
				char[] charSpaces = new char[delimiter.length()];
				Arrays.fill(charSpaces, ' ');
				AttributedString spaces =
					new AttributedString(new String(charSpaces), offcutColor, getMetrics());
				as = new CompositeAttributedString(new AttributedString[] { as, spaces });
			}
			elements[count] = new TextFieldElement(as, count, 0);
		}

		if (tooMany) {
			AttributedString as = new AttributedString(MORE_XREFS_STRING, color, getMetrics());
			elements[elements.length - 1] = new TextFieldElement(as, count - 1, 0);
		}

		return ListingTextField.createPackedTextField(this, proxy, elements, startX + varWidth,
			width, maxXRefs, hlProvider);
	}

	protected AttributedString createRefTypeAttributedString(Reference reference,
			AttributedString referenceString) {
		AttributedString fullReferenceString = referenceString;
		if (reference.getReferenceType().isRead() && reference.getReferenceType().isWrite()) {
			AttributedString typeString = new AttributedString("(R", readColor, getMetrics());
			fullReferenceString = new CompositeAttributedString(
				new AttributedString[] { fullReferenceString, typeString });
			typeString = new AttributedString("W)", writeColor, getMetrics());
			return new CompositeAttributedString(
				new AttributedString[] { fullReferenceString, typeString });
		}

		Color displayColor = color;
		if (reference.getReferenceType().isRead() || reference.getReferenceType().isIndirect()) {
			displayColor = readColor;
		}
		else if (reference.getReferenceType().isWrite()) {
			displayColor = writeColor;
		}
		else if (reference.getReferenceType().isData()) {
			displayColor = otherColor;
		}

		AttributedString typeString =
			new AttributedString(getRefTypeDisplayString(reference), displayColor, getMetrics());
		return new CompositeAttributedString(
			new AttributedString[] { fullReferenceString, typeString });
	}

	protected String getPrefix(Program program, Reference reference, Function currentFunction) {
		String prefix = "";

		Address fromAddress = reference.getFromAddress();
		if (displayBlockName) {
			prefix = getBlockName(program, fromAddress) + ":";
		}

		if (!displayLocalNamespace && !displayNonLocalNamespace) {
			return prefix; // no namespaces being shown
		}

		Function refFunction = program.getListing().getFunctionContaining(fromAddress);
		if (refFunction == null) {
			return prefix;
		}

		boolean isLocal = refFunction.equals(currentFunction);
		if (!isLocal) {
			if (displayNonLocalNamespace) {
				return prefix + refFunction.getName() + ":";
			}
			return prefix; // this means different function, but not displaying other namespaces
		}

		// O.K., we ARE from the same function, how to display it?
		if (!displayLocalNamespace) {
			return prefix;
		}

		// use the namespace name or a custom, user-defined value
		if (useLocalPrefixOverride) {
			return prefix + localPrefixText;
		}
		return prefix + currentFunction.getName() + ":";

	}

	private String getRefTypeDisplayString(Reference reference) {
		RefType refType = reference.getReferenceType();
		if (reference instanceof ThunkReference) {
			return "(T)";
		}
		if (refType instanceof DataRefType) {
			if (refType.isRead() || refType.isIndirect()) {
				return "(R)";
			}
			else if (refType.isWrite()) {
				return "(W)";
			}
			else if (refType.isData()) {
				return "(*)";
			}
		}
		if (refType.isCall()) {
			return "(c)";
		}
		else if (refType.isJump()) {
			return "(j)";
		}
		return "";
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (!(loc instanceof XRefFieldLocation)) {
			return null;
		}

		XRefFieldLocation xRefLoc = (XRefFieldLocation) loc;
		int xrefPos = xRefLoc.getCharOffset();
		int xrefIndex = xRefLoc.getIndex();
		if (!hasSamePath(bf, loc)) {
			return null;
		}

		return createFieldLocation(xrefPos, xrefIndex, (ListingTextField) bf, index, fieldNum);
	}

	protected FieldLocation createFieldLocation(int xrefPos, int xrefIndex, ListingTextField field,
			BigInteger index, int fieldNum) {

		RowColLocation loc = field.dataToScreenLocation(xrefIndex, xrefPos);

		return new FieldLocation(index, fieldNum, loc.row(), loc.col());
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (obj == null || !(obj instanceof CodeUnit)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;
		ListingTextField field = (ListingTextField) getField(bf.getProxy(), 0);
		if (field == null) {
			return null;
		}

		RowColLocation loc = field.screenToDataLocation(row, col);
		int index = loc.row();
		Reference[] xrefs = XReferenceUtil.getXReferences(cu, maxXRefs + 1);
		if (sortChoice == SORT_CHOICE.Address) {
			Arrays.sort(xrefs);
		}
		else {
			Arrays.sort(xrefs, typeComparator);
		}

		Address refAddr = null;
		if (index < xrefs.length) {
			refAddr = xrefs[index].getFromAddress();
		}
		else {
			Reference[] offcuts = XReferenceUtil.getOffcutXReferences(cu, maxXRefs);
			if (sortChoice == SORT_CHOICE.Address) {
				Arrays.sort(offcuts);
			}
			else {
				Arrays.sort(offcuts, typeComparator);
			}
			if (index < xrefs.length + offcuts.length) {
				refAddr = offcuts[index - xrefs.length].getFromAddress();
			}
		}

		if (refAddr != null) {
			int[] cpath = null;
			if (cu instanceof Data) {
				cpath = ((Data) cu).getComponentPath();
			}
			return new XRefFieldLocation(cu.getProgram(), cu.getMinAddress(), cpath, refAddr, index,
				loc.col());
		}
		return null;
	}

	protected String getBlockName(Program pgm, Address addr) {
		Memory mem = pgm.getMemory();
		MemoryBlock block = mem.getBlock(addr);
		if (block != null) {
			return block.getName();
		}
		return "";
	}

	/**
	 * Get an address location for this object.
	 *
	 * @param obj object to get location from
	 * @return the address
	 */
	protected Address getXRefLocation(Object obj) {
		if (obj == null || !(obj instanceof CodeUnit)) {
			return null;
		}
		return ((CodeUnit) obj).getMinAddress();
	}

	protected Program getProgram(Object obj) {
		if (obj == null || !(obj instanceof CodeUnit)) {
			return null;
		}
		return ((CodeUnit) obj).getProgram();
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
			ToolOptions toolOptions, ToolOptions fieldOptions) {
		return new XRefFieldFactory(formatModel, provider, toolOptions, fieldOptions);
	}
}
