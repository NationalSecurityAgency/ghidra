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
import java.beans.PropertyEditor;
import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Predicate;

import javax.swing.event.ChangeListener;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.XReferenceUtils;
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
import util.CollectionUtils;

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
	private static final String DELIMITER_KEY = GROUP_TITLE + Options.DELIMITER + "Delimiter";
	static final String MAX_XREFS_KEY =
		GROUP_TITLE + Options.DELIMITER + "Maximum Number of XREFs to Display";
	private static final String DISPLAY_BLOCK_NAME_KEY =
		GROUP_TITLE + Options.DELIMITER + "Display Local Block";
	private static final String SORT_OPTION_KEY =
		GROUP_TITLE + Options.DELIMITER + "Sort References by";
	private static final String DISPLAY_REFERENCE_TYPE_KEY =
		GROUP_TITLE + Options.DELIMITER + "Display Reference Type";
	private final static String NAMESPACE_OPTIONS_KEY =
		GROUP_TITLE + Options.DELIMITER + "Display Namespace";
	static final String GROUP_BY_FUNCTION_KEY =
		GROUP_TITLE + Options.DELIMITER + "Group by Function";

	private PropertyEditor namespaceOptionsEditor = new NamespacePropertyEditor();

	protected Color offcutColor;
	protected Color readColor;
	protected Color writeColor;
	protected Color otherColor;
	protected String delim = DELIMITER;
	protected boolean displayBlockName;
	protected boolean groupByFunction;
	protected int maxXRefs = MAX_XREFS;
	protected boolean displayRefType = true;
	protected Comparator<Reference> typeComparator;
	protected boolean displayLocalNamespace;
	protected boolean displayNonLocalNamespace;
	protected boolean useLocalPrefixOverride;
	protected String localPrefixText;

	private BrowserCodeUnitFormat codeUnitFormat;
	private ChangeListener codeUnitFormatListener = e -> XRefFieldFactory.this.model.update();

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
		fieldOptions.registerOption(DELIMITER_KEY, DELIMITER, hl,
			"Delimiter string used for separating multiple xrefs.");
		fieldOptions.registerOption(DISPLAY_BLOCK_NAME_KEY, false, hl,
			"Prepends xref addresses with the " +
				"name of the memory block containing the xref address.");
		fieldOptions.registerOption(MAX_XREFS_KEY, MAX_XREFS, hl,
			"Sets the maximum number of xrefs to display.");
		fieldOptions.registerOption(DISPLAY_REFERENCE_TYPE_KEY, true, hl, "Appends xref type.");
		fieldOptions.registerOption(SORT_OPTION_KEY, SORT_CHOICE.Address, hl,
			"How to sort the xrefs");
		fieldOptions.registerOption(GROUP_BY_FUNCTION_KEY, false, hl,
			"True signals to group all xrefs by the containing calling function.");

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

		delim = fieldOptions.getString(DELIMITER_KEY, DELIMITER);
		displayBlockName = fieldOptions.getBoolean(DISPLAY_BLOCK_NAME_KEY, false);

		maxXRefs = fieldOptions.getInt(MAX_XREFS_KEY, MAX_XREFS);
		sortChoice = fieldOptions.getEnum(SORT_OPTION_KEY, SORT_CHOICE.Address);
		displayRefType = fieldOptions.getBoolean(DISPLAY_REFERENCE_TYPE_KEY, true);
		groupByFunction = fieldOptions.getBoolean(GROUP_BY_FUNCTION_KEY, false);

		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(hl);

		setupNamespaceOptions(fieldOptions);

		// Create code unit format and associated options - listen for changes
		codeUnitFormat = new BrowserCodeUnitFormat(fieldOptions, true);
		codeUnitFormat.addChangeListener(codeUnitFormatListener);
	}

	private void setupNamespaceOptions(Options fieldOptions) {
		// we need to install a custom editor that allows us to edit a group of related options
		fieldOptions.registerOption(NAMESPACE_OPTIONS_KEY, OptionType.CUSTOM_TYPE,
			new NamespaceWrappedOption(), null, "Adjusts the XREFs Field namespace display",
			namespaceOptionsEditor);
		CustomOption customOption = fieldOptions.getCustomOption(NAMESPACE_OPTIONS_KEY, null);
		fieldOptions.getOptions(NAMESPACE_OPTIONS_KEY)
				.setOptionsHelpLocation(
					new HelpLocation("CodeBrowserPlugin", "XREFs_Field"));
		if (!(customOption instanceof NamespaceWrappedOption)) {
			throw new AssertException(
				"Someone set an option for " + NAMESPACE_OPTIONS_KEY +
					" that is not the expected " +
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
		if (optionName.equals(DELIMITER_KEY)) {
			delim = (String) newValue;
			model.update();
		}
		else if (optionName.equals(DISPLAY_BLOCK_NAME_KEY)) {
			displayBlockName = (Boolean) newValue;
			model.update();
		}
		else if (optionName.equals(DISPLAY_REFERENCE_TYPE_KEY)) {
			displayRefType = (Boolean) newValue;
			model.update();
		}
		else if (optionName.equals(MAX_XREFS_KEY)) {
			setMaxSize(((Integer) newValue).intValue(), options);
			model.update();
		}
		else if (optionName.equals(SORT_OPTION_KEY)) {
			sortChoice = (SORT_CHOICE) newValue;
			model.update();
		}
		else if (optionName.equals(NAMESPACE_OPTIONS_KEY)) {
			setupNamespaceOptions(options);
			model.update();
		}
		else if (optionName.equals(GROUP_BY_FUNCTION_KEY)) {
			groupByFunction = (Boolean) newValue;
			model.update();
		}
	}

	private void setMaxSize(int n, Options options) {
		if (n < 1) {
			n = 1;
			options.setInt(MAX_XREFS_KEY, 1);
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

		if (!(obj instanceof CodeUnit)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;
		List<Reference> xrefs = XReferenceUtils.getXReferences(cu, maxXRefs + 1);
		int maxOffcuts = Math.max(0, maxXRefs - xrefs.size());
		List<Reference> offcuts = XReferenceUtils.getOffcutXReferences(cu, maxOffcuts);
		if (sortChoice == SORT_CHOICE.Address) {
			xrefs.sort(null);
			offcuts.sort(null);
		}
		else {
			xrefs.sort(typeComparator);
			offcuts.sort(typeComparator);
		}

		if (groupByFunction) {
			return getFieldByFunction(proxy, varWidth, xrefs, offcuts);
		}
		return getFieldByAddress(proxy, varWidth, xrefs, offcuts);
	}

	/*
		Create a series of fields: 1 row per function and the xrefs it contains and 1 wrapping
		field for all xrefs not in any function.  The wrapping field will go below the function
		based xrefs.  It will look something like this:
			
			foo1: 123, 223
			foo2: 323, 333
			423, 433, 567,
			899, [more]
		
		The fields and elements created by this method have this structure:
		
			XrefListingField
			
				CompositeVerticalLayoutTextField
					
					0+ ClippingTextField
							CompositeFieldElement
								XrefFieldEleent
									XrefAttributedString
									
					0+ FlowLayoutTextField
							XrefFieldEleent
									XrefAttributedString
									
									
	*/
	private ListingField getFieldByFunction(ProxyObj<?> proxy, int varWidth,
			List<Reference> xrefs, List<Reference> offcuts) {

		int totalXrefs = xrefs.size() + offcuts.size();
		if (totalXrefs == 0) {
			return null;
		}

		boolean tooMany = totalXrefs > maxXRefs;

		Object obj = proxy.getObject();
		CodeUnit cu = (CodeUnit) obj;
		Program program = cu.getProgram();
		FontMetrics metrics = getMetrics();
		FunctionManager functionManager = program.getFunctionManager();

		//
		// Bin all xrefs by containing function, which may be null
		//
		List<Reference> noFunction = new ArrayList<>();
		TreeMap<Function, List<Reference>> xrefsByFunction = new TreeMap<>((f1, f2) -> {
			return f1.getEntryPoint().compareTo(f2.getEntryPoint());
		});
		for (Reference ref : CollectionUtils.asIterable(xrefs, offcuts)) {

			Function function = functionManager.getFunctionContaining(ref.getFromAddress());
			if (function == null) {
				noFunction.add(ref);
			}
			else {
				xrefsByFunction.computeIfAbsent(function, r -> new ArrayList<>()).add(ref);
			}
		}

		//
		// Create the function rows
		//
		Set<Reference> offcutSet = new HashSet<>(offcuts);
		Predicate<Reference> isOffcut = r -> offcutSet.contains(r);
		HighlightFactory hlFactory =
			new FieldHighlightFactory(hlProvider, getClass(), proxy.getObject());
		Function currentFunction = functionManager.getFunctionContaining(cu.getMinAddress());
		List<TextField> functionRows =
			createXrefRowsByFunction(program, currentFunction, xrefsByFunction, isOffcut, varWidth,
				hlFactory);

		//
		// TODO maxXRefs makes sense when simply displaying xrefs.  What does max mean when
		//      binning xrefs by function.  Currently, we use the max as the max row count, but
		//      this may need to be changed and it may require a new tool option.
		//

		int maxLines = maxXRefs;
		int availableLines = maxLines - functionRows.size();
		if (tooMany) {
			// save room for the "more" field at the end
			availableLines -= 1;
		}

		//
		// Create the row for xrefs not in a function
		//

		//
		// Note: the objects we build here want the 'data' row as a parameter, not the screen row.
		//       Out screen rows are what we are building to display; a data row we are here
		//       defining to be a single xref.   This is a somewhat arbitrary decision.
		int dataRow = totalXrefs - noFunction.size();
		TextField noFunctionXrefsField =
			createWrappingXrefRow(program, dataRow, noFunction, currentFunction, isOffcut,
				availableLines, hlFactory);

		List<TextField> allFields = new ArrayList<>();
		allFields.addAll(functionRows);
		if (noFunctionXrefsField != null) {
			allFields.add(noFunctionXrefsField);
		}

		int newStartX = startX + varWidth;
		if (tooMany) {
			// add the [more] element
			int lastRow = allFields.size() - 1;
			AttributedString as = new AttributedString(MORE_XREFS_STRING, color, metrics);
			TextFieldElement moreElement = new TextFieldElement(as, lastRow, 0);
			ClippingTextField ctf = new ClippingTextField(newStartX, width, moreElement, hlFactory);
			allFields.add(ctf);
		}

		CompositeVerticalLayoutTextField compositefield =
			new CompositeVerticalLayoutTextField(allFields, newStartX, width, maxXRefs, hlFactory);
		return new XrefListingField(this, proxy, compositefield);
	}

	private List<TextField> createXrefRowsByFunction(Program program, Function currentFunction,
			TreeMap<Function, List<Reference>> xrefsByFunction, Predicate<Reference> isOffcut,
			int varWidth,
			HighlightFactory hlFactory) {

		FontMetrics metrics = getMetrics();
		AttributedString delimiter = new AttributedString(delim, Color.BLACK, metrics);

		int row = 0;
		List<FieldElement> elements = new ArrayList<>();
		Set<Entry<Function, List<Reference>>> entries = xrefsByFunction.entrySet();
		for (Entry<Function, List<Reference>> entry : entries) {

			//
			// Example row: functionName: 1234(c), 1238(c)
			//

			List<Reference> refs = entry.getValue();
			Function fromFunction = entry.getKey();
			String functionName = fromFunction.getName();
			int refCount = refs.size();
			String sizeText = ": ";
			if (refCount > 1) {
				sizeText = "[" + refs.size() + "]: ";
			}
			String text = functionName + sizeText;
			AttributedString nameString =
				new AttributedString(text, color, metrics);
			List<XrefFieldElement> rowElements = new ArrayList<>();
			Reference firstRef = refs.get(0);
			XrefAttributedString xrefString =
				new XrefAttributedString(firstRef, nameString);
			rowElements.add(new XrefFieldElement(xrefString, row, 0));

			//
			// TODO how many xrefs to display per function?
			//
			int n = Math.min(10, refs.size());
			for (int i = 0; i < n; i++) {

				boolean isLast = i == n - 1;
				Reference ref = refs.get(i);
				String prefix = getMergedPrefix(program, ref, currentFunction, fromFunction);
				XrefFieldElement element =
					createFunctionElement(program, prefix, ref, row, isLast ? null : delimiter,
						isOffcut.test(ref));
				rowElements.add(element);
			}

			elements.add(new CompositeFieldElement(rowElements));

			row++;
		}

		int newStartX = startX + varWidth;
		List<TextField> textFields = new ArrayList<>();
		for (FieldElement element : elements) {
			textFields.add(new ClippingTextField(newStartX, width, element, hlFactory));
		}

		return textFields;
	}

	private TextField createWrappingXrefRow(Program program, int startRow, List<Reference> xrefs,
			Function currentFunction, Predicate<Reference> isOffcut, int availableLines,
			HighlightFactory hlFactory) {

		FontMetrics metrics = getMetrics();
		AttributedString delimiter = new AttributedString(delim, Color.BLACK, metrics);
		int row = startRow;
		List<XrefFieldElement> elements = new ArrayList<>();
		for (Reference ref : xrefs) {

			String prefix = getPrefix(program, ref, currentFunction, null);
			XrefFieldElement element =
				createReferenceElement(program, prefix, ref, row, delimiter, isOffcut.test(ref));
			elements.add(element);
			row++;
		}

		// add all elements to a field that will wrap as needed
		if (!elements.isEmpty()) {
			List<FieldElement> fieldElements = toFieldElements(elements, false);
			return new FlowLayoutTextField(fieldElements, startX, width, availableLines, hlFactory);
		}

		return null;
	}

	/*
		Create a series of fields: 1 row per function and the xrefs it contains and 1 wrapping
		field for all xrefs not in any function.  The wrapping field will go below the function
		based xrefs.  It will look something like this:
						
			foo1:423,
			foo1:433,
			foo2:567,
			899, [more]
		
		The fields and elements created by this method have this structure:
		
			XrefListingField
				1+ FlowLayoutTextField
						XrefFieldEleent
							XrefAttributedString
								
								
	*/
	private ListingField getFieldByAddress(ProxyObj<?> proxy, int varWidth, List<Reference> xrefs,
			List<Reference> offcuts) {

		int totalXrefs = xrefs.size() + offcuts.size();
		if (totalXrefs == 0) {
			return null;
		}

		Object obj = proxy.getObject();
		CodeUnit cu = (CodeUnit) obj;
		Program program = cu.getProgram();
		FontMetrics metrics = getMetrics();
		AttributedString delimiter = new AttributedString(delim, Color.BLACK, metrics);

		Set<Reference> offcutSet = new HashSet<>(offcuts);
		Predicate<Reference> isOffcut = r -> offcutSet.contains(r);

		boolean tooMany = totalXrefs > maxXRefs;
		List<XrefFieldElement> elements = new ArrayList<>();
		FunctionManager functionManager = program.getFunctionManager();
		Function currentFunction = functionManager.getFunctionContaining(cu.getMinAddress());
		int n = tooMany ? maxXRefs : totalXrefs;
		int count = 0;
		for (; count < xrefs.size() && count < n; count++) {
			Reference ref = xrefs.get(count);
			String prefix = getPrefix(program, ref, currentFunction);
			elements.add(
				createReferenceElement(program, prefix, ref, count, delimiter, isOffcut.test(ref)));
		}

		for (int i = 0; i < offcuts.size() && count < n; i++, count++) {
			Reference ref = offcuts.get(i);
			String prefix = getPrefix(program, ref, currentFunction);
			elements.add(
				createReferenceElement(program, prefix, ref, count, delimiter, isOffcut.test(ref)));
		}

		if (!tooMany) {
			XrefFieldElement lastElement = elements.get(elements.size() - 1);
			lastElement.hideDelimiter();
		}

		List<FieldElement> fieldElements = toFieldElements(elements, tooMany);
		return createPackedTextField(proxy, varWidth, fieldElements);
	}

	// note: this method was inspired by ListingTextField.createPackedTextField()
	private XrefListingField createPackedTextField(ProxyObj<?> proxy, int varWidth,
			List<FieldElement> list) {

		// assumption: the given array has been limited to the maxXref size already
		int n = list.size();
		HighlightFactory hlFactory =
			new FieldHighlightFactory(hlProvider, getClass(), proxy.getObject());
		TextField field =
			new FlowLayoutTextField(list, startX + varWidth, width, n, hlFactory);
		return new XrefListingField(this, proxy, field);
	}

	private List<FieldElement> toFieldElements(List<XrefFieldElement> list, boolean showEllipses) {

		List<FieldElement> fieldElements = new ArrayList<>(list);
		if (showEllipses) {
			// add the 'more' string
			int lastRow = list.size() - 1;
			AttributedString as = new AttributedString(MORE_XREFS_STRING, color, getMetrics());
			fieldElements.add(new TextFieldElement(as, lastRow, 0));
		}
		return fieldElements;
	}

	private XrefFieldElement createFunctionElement(Program program, String prefix, Reference ref,
			int row, AttributedString delimiter, boolean isOffcut) {

		FontMetrics metrics = getMetrics();
		String addressString = ref.getFromAddress().toString(prefix);
		Color refColor = isOffcut ? offcutColor : color;
		AttributedString addressPart = new AttributedString(addressString, refColor, metrics);
		if (displayRefType) {
			addressPart = createRefTypeAttributedString(ref, addressPart);
		}

		XrefAttributedString xrefString =
			new XrefAttributedString(ref, addressPart, delimiter);
		if (delimiter == null) {
			xrefString.hideDelimiter();
		}

		return new XrefFieldElement(xrefString, row, 0);
	}

	private XrefFieldElement createReferenceElement(Program program, String prefix, Reference ref,
			int row, AttributedString delimiter, boolean isOffcut) {

		FontMetrics metrics = getMetrics();
		String addressString = ref.getFromAddress().toString(prefix);
		Color refColor = isOffcut ? offcutColor : color;
		AttributedString as = new AttributedString(addressString, refColor, metrics);
		if (displayRefType) {
			as = createRefTypeAttributedString(ref, as);
		}

		XrefAttributedString xrefString =
			new XrefAttributedString(ref, as, delimiter);
		return new XrefFieldElement(xrefString, row, 0);
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

		Address fromAddress = reference.getFromAddress();
		Function fromFunction = program.getListing().getFunctionContaining(fromAddress);
		return getPrefix(program, reference, currentFunction, fromFunction);
	}

	private String getMergedPrefix(Program program, Reference reference, Function currentFunction,
			Function fromFunction) {

		String prefix = "";
		Address fromAddress = reference.getFromAddress();
		if (displayBlockName) {
			prefix = getBlockName(program, fromAddress) + ":";
		}

		if (!displayLocalNamespace && !displayNonLocalNamespace) {
			return prefix; // no namespaces being shown
		}

		boolean isLocal = Objects.equals(currentFunction, fromFunction);
		if (isLocal && useLocalPrefixOverride) {
			return prefix + localPrefixText;
		}
		return prefix;
	}

	private String getPrefix(Program program, Reference reference, Function currentFunction,
			Function fromFunction) {

		String prefix = "";
		Address fromAddress = reference.getFromAddress();
		if (displayBlockName) {
			prefix = getBlockName(program, fromAddress) + ":";
		}

		if (!displayLocalNamespace && !displayNonLocalNamespace) {
			return prefix; // no namespaces being shown
		}

		if (fromFunction == null) {
			return prefix;
		}

		boolean isLocal = fromFunction.equals(currentFunction);
		if (!isLocal) {
			if (displayNonLocalNamespace) {
				return prefix + fromFunction.getName() + ":";
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
	public ProgramLocation getProgramLocation(int row, int col, ListingField listingField) {
		Object obj = listingField.getProxy().getObject();
		if (obj == null || !(obj instanceof CodeUnit)) {
			return null;
		}

		if (!(listingField instanceof XrefListingField)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;

		int[] cpath = null;
		if (cu instanceof Data) {
			cpath = ((Data) cu).getComponentPath();
		}

		XrefListingField field = (XrefListingField) listingField;
		FieldElement element = field.getFieldElement(row, col);
		RowColLocation loc = field.screenToDataLocation(row, col);
		if (element instanceof XrefFieldElement) {
			XrefFieldElement xrefElement = (XrefFieldElement) element;
			Reference xref = xrefElement.getXref();
			Address refAddr = xref.getFromAddress();
			return new XRefFieldLocation(cu.getProgram(), cu.getMinAddress(), cpath, refAddr, row,
				loc.col());
		}

		String text = element.getText();
		if (MORE_XREFS_STRING.equals(text)) {
			return new XRefFieldLocation(cu.getProgram(), cu.getMinAddress(), cpath, null, row,
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

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class XrefAttributedString extends CompositeAttributedString {

		private AttributedString content;
		private AttributedString delimiter;
		private Reference xref;

		public XrefAttributedString(Reference xref, AttributedString content) {
			super(content);
			this.content = content;
			this.xref = xref;
		}

		public XrefAttributedString(Reference xref, AttributedString content,
				AttributedString delimiter) {
			super(content, delimiter);
			this.content = content;
			this.delimiter = delimiter;
			this.xref = xref;
		}

		void hideDelimiter() {
			AttributedString source = delimiter;
			if (source == null) {
				source = content;
			}

			int length = delimiter == null ? 1 : delimiter.length();

			// Use spaces instead of an empty string; this added to prevent a situation where
			// resizing field to a particular size, resulted in layout of references to be strange
			char[] charSpaces = new char[length];
			Arrays.fill(charSpaces, ' ');
			AttributedString spaces =
				new AttributedString(new String(charSpaces), source.getColor(0),
					source.getFontMetrics(0));
			attributedStrings[attributedStrings.length - 1] = spaces;
		}

		Reference getXref() {
			return xref;
		}
	}

	private class XrefFieldElement extends TextFieldElement {

		private XrefAttributedString xrefString;

		public XrefFieldElement(XrefAttributedString xrefString, int row, int column) {
			super(xrefString, row, column);
			this.xrefString = xrefString;
		}

		void hideDelimiter() {
			xrefString.hideDelimiter();
		}

		Reference getXref() {
			return xrefString.getXref();
		}
	}

	private class XrefListingField extends ListingTextField {

		XrefListingField(XRefFieldFactory factory, ProxyObj<?> proxy, TextField field) {
			super(factory, proxy, field);
		}

	}
}
