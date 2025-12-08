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
import docking.widgets.fieldpanel.support.*;
import ghidra.GhidraOptions;
import ghidra.app.util.*;
import ghidra.app.util.viewer.field.ListingColors.FunctionColors;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.LabelString.LabelType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

/**
 * Helper class to store the options of the
 * OperandFieldFactory and SubDataFieldFactory
 */
abstract class OperandFieldHelper extends FieldFactory {

	private final static String ENABLE_WORD_WRAP_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + FieldUtils.WORD_WRAP_OPTION_NAME;
	private final static String MAX_DISPLAY_LINES_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Maximum Lines To Display";
	private final static String UNDERLINE_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Underline References";
	private final static String SPACE_AFTER_SEPARATOR_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Add Space After Separator";
	private final static String WRAP_ON_SEMICOLON_OPTION =
		GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER + "Wrap on Semicolons";
	private final static OperandFieldElement LINE_BREAK = new OperandFieldElement(null, 0, 0, 0);

	public enum UNDERLINE_CHOICE {
		Hidden, All, None
	}

	private SymbolInspector inspector;

	private ColorStyleAttributes addressAttributes = new ColorStyleAttributes();
	private ColorStyleAttributes badRefAttributes = new ColorStyleAttributes();
	private ColorStyleAttributes separatorAttributes = new ColorStyleAttributes();
	private ColorStyleAttributes scalarAttributes = new ColorStyleAttributes();
	private ColorStyleAttributes variableRefAttributes = new ColorStyleAttributes();
	private ColorStyleAttributes registerAttributes = new ColorStyleAttributes();

	private UNDERLINE_CHOICE underlineChoice = UNDERLINE_CHOICE.Hidden;
	private boolean isWordWrap = false;
	private int maxDisplayLines = 2;
	private boolean spaceAfterSeparator = false;
	private boolean wrapOnSemicolon = false;

	protected BrowserCodeUnitFormat codeUnitFormat;
	private ChangeListener codeUnitFormatListener = e -> OperandFieldHelper.this.model.update();

	/**
	 * Constructor - for use by the field format
	 * @param name the name of the field
	 */
	OperandFieldHelper(String name) {
		super(name);
	}

	/**
	 * Constructor
	 * @param name the name of the field.
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightlightProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	OperandFieldHelper(String name, FieldFormatModel model, ListingHighlightProvider hlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		super(name, model, hlProvider, displayOptions, fieldOptions);

		setOptions(displayOptions);

		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "Operands_Field");
		fieldOptions.registerOption(ENABLE_WORD_WRAP_OPTION, false, hl,
			"Enables word wrapping of strings in the operands field.");
		fieldOptions.registerOption(MAX_DISPLAY_LINES_OPTION, 2, hl,
			"The maximum number of lines used to display the strings in the operands field.");
		fieldOptions.registerOption(UNDERLINE_OPTION, UNDERLINE_CHOICE.Hidden, hl,
			"Select 'All' to underline any operand field that has a reference; " +
				"select 'Hidden' to underline operand fields that have non-primary references;\n" +
				"select 'None' for no underlines.");
		fieldOptions.registerOption(SPACE_AFTER_SEPARATOR_OPTION, false, hl,
			"Add space between separator and next operand");
		fieldOptions.registerOption(WRAP_ON_SEMICOLON_OPTION, false, hl,
			"Wrap operand field on semicolons");

		setMaximumLinesToDisplay(fieldOptions.getInt(MAX_DISPLAY_LINES_OPTION, 2), fieldOptions);
		isWordWrap = fieldOptions.getBoolean(ENABLE_WORD_WRAP_OPTION, false);
		underlineChoice = fieldOptions.getEnum(UNDERLINE_OPTION, UNDERLINE_CHOICE.Hidden);
		spaceAfterSeparator = fieldOptions.getBoolean(SPACE_AFTER_SEPARATOR_OPTION, false);
		wrapOnSemicolon = fieldOptions.getBoolean(WRAP_ON_SEMICOLON_OPTION, false);

		inspector = new SymbolInspector(displayOptions, null);

		// Create code unit format and associated options - listen for changes
		codeUnitFormat = new BrowserCodeUnitFormat(fieldOptions, true);
		codeUnitFormat.addChangeListener(codeUnitFormatListener);
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		setOptions(options);
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		boolean updateModel = false;
		switch (optionName) {
			case MAX_DISPLAY_LINES_OPTION:
				setMaximumLinesToDisplay(((Integer) newValue).intValue(), options);
				updateModel = true;
				break;
			case ENABLE_WORD_WRAP_OPTION:
				isWordWrap = ((Boolean) newValue).booleanValue();
				updateModel = true;
				break;
			case UNDERLINE_OPTION:
				underlineChoice = (UNDERLINE_CHOICE) newValue;
				updateModel = true;
				break;
			case SPACE_AFTER_SEPARATOR_OPTION:
				spaceAfterSeparator = ((Boolean) newValue).booleanValue();
				updateModel = true;
				break;
			case WRAP_ON_SEMICOLON_OPTION:
				wrapOnSemicolon = ((Boolean) newValue).booleanValue();
				updateModel = true;
				break;
		}

		if (updateModel) {
			model.update();
		}
	}

	private void setMaximumLinesToDisplay(int maxLines, Options options) {
		if (maxLines < 1) {
			maxLines = 1;
			options.setInt(MAX_DISPLAY_LINES_OPTION, maxLines);
		}
		this.maxDisplayLines = maxLines;
	}

	FieldLocation getFieldLocation(BigInteger index, int fieldNum, ListingField field, int opIndex,
			int column) {
		if (field instanceof ListingTextField listingField) {
			RowColLocation rcl = listingField.dataToScreenLocation(opIndex, column);
			return new FieldLocation(index, fieldNum, rcl.row(), rcl.col());
		}
		else if (field instanceof ImageFactoryField) {
			return new FieldLocation(index, fieldNum, 0, 0);
		}
		return null;
	}

	ListingField getField(Object obj, ProxyObj<?> proxy, int varWidth) {
		if (!enabled) {
			return null;
		}
		if (obj instanceof Instruction) {
			return getFieldForInstruction((Instruction) obj, proxy, varWidth);
		}
		else if (obj instanceof Data) {
			return getFieldForData((Data) obj, proxy, varWidth);
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField lf) {
		Object obj = lf.getProxy().getObject();

		if (lf instanceof ImageFactoryField) {
			Data data = (Data) obj;
			Object value = data.getValue();
			if (value instanceof DataImage || value instanceof Icon) {
				return new ResourceFieldLocation(data.getProgram(), data.getMinAddress(),
					data.getComponentPath(), codeUnitFormat.getDataValueRepresentationString(data),
					0, col, data);
			}
			// else might be a Playable
		}

		if (!(lf instanceof ListingTextField)) {
			return null;
		}

		ListingTextField btf = (ListingTextField) lf;
		FieldElement fieldElement = btf.getFieldElement(row, col);
		if (!(fieldElement instanceof OperandFieldElement)) {
			return null;
		}

		OperandFieldElement element = (OperandFieldElement) fieldElement;
		int opIndex = element.getOperandIndex();
		int subOpIndex = element.getOperandSubIndex();
		RowColLocation translatedLocation = btf.screenToDataLocation(row, col);

		int dataCol = translatedLocation.col();
		if (obj instanceof Instruction) {
			return createInstructionLocation(obj, element, opIndex, subOpIndex, dataCol);
		}
		else if (obj instanceof Data) {
			return createDataLocation(obj, opIndex, subOpIndex, dataCol, col);
		}
		return null;
	}

	private ProgramLocation createDataLocation(Object obj, int opIndex, int subOpIndex,
			int dataCol, int screenCol) {

		Data data = (Data) obj;
		Address refAddr = null;
		Program program = data.getProgram();
		ReferenceManager referenceManager = program.getReferenceManager();
		Address minAddress = data.getMinAddress();
		Reference primaryReference = referenceManager.getPrimaryReferenceFrom(minAddress, 0);
		Object value = data.getValue();
		if (primaryReference != null) {
			refAddr = primaryReference.getToAddress();
		}
		else {
			if (value instanceof Address) {
				refAddr = (Address) value;
			}
		}

		if (value instanceof Scalar) {
			Scalar scalar = (Scalar) value;
			EquateTable equateTable = program.getEquateTable();
			Equate equate = equateTable.getEquate(minAddress, opIndex, scalar.getValue());
			if (equate != null) {
				return new EquateOperandFieldLocation(program, minAddress, refAddr,
					equate.getDisplayName(), equate, opIndex, subOpIndex, dataCol);
			}
		}
		return new OperandFieldLocation(program, minAddress, data.getComponentPath(), refAddr,
			codeUnitFormat.getDataValueRepresentationString(data), 0, screenCol);
	}

	private ProgramLocation createInstructionLocation(Object obj, OperandFieldElement element,
			int opIndex, int subOpIndex, int dataCol) {

		Instruction inst = (Instruction) obj;
		OperandRepresentationList opRepList =
			codeUnitFormat.getOperandRepresentationList(inst, opIndex);
		Address minAddress = inst.getMinAddress();
		Address refAddr = null;
		VariableOffset variableOffset = null;
		Program program = inst.getProgram();
		if (opRepList == null) {
			return new OperandFieldLocation(program, minAddress, variableOffset,
				refAddr, "<UNSUPPORTED>", opIndex, subOpIndex, dataCol);
		}

		String repStr = opRepList.toString();
		if (subOpIndex >= 0 && opRepList.size() > subOpIndex) {
			Object rep = opRepList.get(subOpIndex);
			if (rep instanceof Address) {
				refAddr = (Address) rep;
			}
			else {
				int extendedRefIndex = repStr.indexOf("=>");
				if (extendedRefIndex < 0 || dataCol <= extendedRefIndex) {
					// only get variable offset if extended reference was not clicked on
					variableOffset = getVariableOffset(rep);
				}
				refAddr = inst.getAddress(opIndex);
				if (refAddr == null) {
					// Check for inferred variable reference
					refAddr = getVariableStorageAddress(inst, opRepList, element.getText());
				}

				if (rep instanceof Equate) {
					Equate equate = (Equate) rep;
					return new EquateOperandFieldLocation(program, minAddress,
						refAddr, repStr, equate, opIndex, subOpIndex, dataCol);
				}
			}
		}

		return new OperandFieldLocation(program, minAddress, variableOffset, refAddr,
			repStr, opIndex, subOpIndex, dataCol);
	}

	private VariableOffset getVariableOffset(Object representation) {
		if (representation instanceof VariableOffset) {
			return (VariableOffset) representation;
		}
		else if (representation instanceof OperandRepresentationList) {
			OperandRepresentationList list = (OperandRepresentationList) representation;
			for (Object innerRepresentation : list) {
				if (innerRepresentation instanceof VariableOffset) {
					return (VariableOffset) innerRepresentation;
				}
			}
		}
		return null;
	}

	private Address getVariableStorageAddress(Instruction inst, OperandRepresentationList opList,
			String string) {
		flattenList(opList);
		for (Object obj : opList) {
			if ((obj instanceof VariableOffset) && string.equals(obj.toString())) {
				Variable var = ((VariableOffset) obj).getVariable();
				if (var == null) {
					continue;
				}
				return var.getMinAddress();
			}
		}
		return null;
	}

	private void flattenList(List<Object> list) {
		for (int i = 0; i < list.size();) {
			Object obj = list.get(i);
			if (obj instanceof List) {
				List<?> subList = (List<?>) list.remove(i);
				int n = i;
				for (Object subObj : subList) {
					list.add(n++, subObj);
				}
			}
			else {
				++i;
			}
		}
	}

	private ListingField getFieldForData(Data data, ProxyObj<?> proxy, int varWidth) {

		Object value = data.getValue();
		if (value instanceof DataImage) {
			return new ImageFactoryField(this, ((DataImage) value).getImageIcon(), proxy,
				getMetrics(), startX + varWidth, width);
		}
		if (value instanceof Icon) {
			return new ImageFactoryField(this, (Icon) value, proxy, getMetrics(), startX + varWidth,
				width);
		}
		else if (value instanceof Playable) {
			return new ImageFactoryField(this, ((Playable) value).getImageIcon(), proxy,
				getMetrics(), startX + varWidth, width);
		}

		OperandRepresentationList dataValueRepresentation =
			codeUnitFormat.getDataValueRepresentation(data);
		boolean underline =
			isUnderlined(data, 0, dataValueRepresentation.isPrimaryReferenceHidden());
		ColorStyleAttributes attributes = dataValueRepresentation.hasError() ? badRefAttributes
				: getAttributesForData(data, value);
		AttributedString as =
			new AttributedString(dataValueRepresentation.toString(), attributes.colorAttribute,
				getMetrics(attributes.styleAttribute), underline, ListingColors.UNDERLINE);
		FieldElement field = new OperandFieldElement(as, 0, 0, 0);

		if (shouldWordWrap(data, dataValueRepresentation)) {
			return ListingTextField.createWordWrappedTextField(this, proxy, field,
				startX + varWidth, width, maxDisplayLines, hlProvider);
		}

		return ListingTextField.createSingleLineTextField(this, proxy, field, startX + varWidth,
			width, hlProvider);
	}

	// a place to update data types that support word wrapping
	private boolean shouldWordWrap(Data data, OperandRepresentationList dataValueRepresentation) {

		if (dataValueRepresentation.hasError()) {
			return true;
		}

		if (!isWordWrap) {
			return false;
		}

		Object value = data.getValue();
		if (value instanceof String) {
			return true;
		}

		DataType dt = data.getDataType();
		if (dt instanceof Enum) {
			return true; // enums use String text for names and these may be ORed together
		}

		return false;
	}

	private ColorStyleAttributes getAttributesForData(Data data, Object value) {
		// if in a union, references only apply to pointers. So if not a pointer use either address
		// or scalar attributes.
		Data parentData = data.getParent();
		if (isInvalidEquate(data)) {
			return badRefAttributes; // Bad equates should be red.
		}
		boolean parentIsaUnion =
			(parentData != null) && (parentData.getDataType() instanceof Union);
		if ((parentIsaUnion && !data.isPointer())) {
			return (value instanceof Address) ? addressAttributes : scalarAttributes;
		}

		return getOpAttributes(data, 0, data.getProgram());
	}

	private ListingField getFieldForInstruction(Instruction inst, ProxyObj<?> proxy, int varWidth) {
		int numOperands = inst.getNumOperands();
		if (numOperands == 0) {
			return null;
		}

		OpFieldResults results = new OpFieldResults(proxy);
		OperandFieldElement separator = createLeadingSeparatorElement(inst);
		if (separator != null) {
			results.add(separator);
		}

		for (int opIndex = 0; opIndex < numOperands; opIndex++) {
			OpInfo opInfo = new OpInfo(inst, opIndex);
			addOperandElements(opInfo, results);
			results.resetCharacterOffset();
		}

		// If this is an operand with no representation objects, don't create a visual element
		if (results.isEmpty()) {
			return null;
		}
		return results.createListingTextField(varWidth);
	}

	private List<FieldElement> breakIntoLines(List<OperandFieldElement> elements) {
		// This method groups all elements between LINE_BREAK elements into composite elements
		// where each composite element will be display on its own line.
		//
		// It does this by collecting elements in the lineElements list until it find a LINE_BREAK
		List<FieldElement> fieldElements = new ArrayList<>();
		List<OperandFieldElement> lineElements = new ArrayList<>();

		for (OperandFieldElement operandFieldElement : elements) {
			if (operandFieldElement == LINE_BREAK) {
				if (!lineElements.isEmpty()) {
					fieldElements.add(new CompositeFieldElement(lineElements));
					lineElements.clear();
				}
			}
			else {
				lineElements.add(operandFieldElement);
			}
		}
		if (!lineElements.isEmpty()) {
			fieldElements.add(new CompositeFieldElement(lineElements));
			lineElements.clear();
		}
		return fieldElements;
	}

	private void addOperandElements(OpInfo opInfo, OpFieldResults results) {

		int subOpIndex = 0;
		if (opInfo.isInvalid()) {
			addOperandErrorElement(opInfo, results);
			return;
		}

		for (; subOpIndex < opInfo.getRepCount(); subOpIndex++) {
			Object opElement = opInfo.getRepElement(subOpIndex);
			addOperandElement(opInfo, results, opElement, subOpIndex);
		}

		//  add in any separator after this operand
		int separatorIndex = opInfo.opIndex + 1;
		OperandFieldElement separator =
			createSeparatorElement(opInfo, results, subOpIndex - 1, separatorIndex);
		if (separator != null) {
			results.add(separator);
		}
	}

	private void addOperandErrorElement(OpInfo opInfo, OpFieldResults results) {

		FontMetrics metrics = getMetrics(badRefAttributes.styleAttribute);
		String text = opInfo.getRepText();
		AttributedString as =
			new AttributedString(text, badRefAttributes.colorAttribute, metrics,
				false, ListingColors.UNDERLINE);
		results.add(new OperandFieldElement(as, opInfo.opIndex, 0, results.characterOffset));

		//  add in any separator after this operand
		int separatorIndex = opInfo.opIndex + 1;
		OperandFieldElement separator = createSeparatorElement(opInfo, results, -1, separatorIndex);
		if (separator != null) {
			results.add(separator);
		}
	}

	private void addOperandSubElements(OpInfo opInfo, OpFieldResults results,
			List<?> elements, int subOpIndex) {

		// Special case: '[->Lib::Foo]' 
		// Most references will paint the label color, typically blue.  For external function calls,
		// the color will change depending on whether the external function is linked.  Handle this 
		// case specially so that the arrow text will be the same color as the library name.
		if (isIndirectReference(elements)) {
			addIndirectReference(opInfo, results, elements, subOpIndex);
			return;
		}

		for (Object element : elements) {
			addOperandElement(opInfo, results, element, subOpIndex);
		}
	}

	private boolean isIndirectReference(List<?> elements) {
		if (elements.size() != 2) {
			return false;
		}

		Object object = elements.get(0);
		String text = object.toString();
		if (!text.equals(CodeUnitFormat.EXTENDED_INDIRECT_REFERENCE_DELIMITER)) {
			return false;
		}

		Object element = elements.get(1);
		return element instanceof LabelString;
	}

	private void addIndirectReference(OpInfo opInfo, OpFieldResults results,
			List<?> elements, int subOpIndex) {

		Object opElement = elements.get(1);
		ColorStyleAttributes attributes = getOpAttributes(opInfo, opElement);

		boolean underline = opInfo.isUnderline();
		Object pointer = elements.get(0).toString();
		String text = pointer + opElement.toString();
		FontMetrics metrics = getMetrics(attributes.styleAttribute);
		AttributedString as = new AttributedString(text, attributes.colorAttribute,
			metrics, underline, ListingColors.UNDERLINE);
		results.add(
			new OperandFieldElement(as, opInfo.opIndex, subOpIndex, results.characterOffset));
	}

	private void addOperandElement(OpInfo opInfo, OpFieldResults results, Object opElement,
			int subOpIndex) {

		if (opElement instanceof VariableOffset variableOffset) {
			addVariableElement(opInfo, results, variableOffset, subOpIndex);
			return;
		}

		if (opElement instanceof List list) {
			addOperandSubElements(opInfo, results, list, subOpIndex);
			return;
		}

		ColorStyleAttributes attributes = getOpAttributes(opInfo, opElement);
		addOperandElementWithAttributes(opInfo, results, opElement, subOpIndex, attributes);
	}

	private void addOperandElementWithAttributes(OpInfo opInfo, OpFieldResults results,
			Object opElement, int subOpIndex, ColorStyleAttributes attributes) {

		boolean underline = opInfo.isUnderline();
		FontMetrics metrics = getMetrics(attributes.styleAttribute);
		AttributedString as = new AttributedString(opElement.toString(), attributes.colorAttribute,
			metrics, underline, ListingColors.UNDERLINE);
		results.add(
			new OperandFieldElement(as, opInfo.opIndex, subOpIndex, results.characterOffset));
		if (wrapOnSemicolon && opElement instanceof Character c && c == ';') {
			results.addLineBreak();
		}
	}

	private void addVariableElement(OpInfo opInfo, OpFieldResults results,
			VariableOffset variableOffset, int subOpIndex) {

		Color color = FunctionColors.VARIABLE;
		Variable variable = variableOffset.getVariable();
		if (variable instanceof Parameter param) {
			if (param.isAutoParameter()) {

				Object opElement = opInfo.getRepElement(subOpIndex);
				addAutoParameterElement(opInfo, results, param, opElement, subOpIndex);
				return;
			}

			Function f = variable.getFunction();
			color = f.hasCustomVariableStorage() ? FunctionColors.PARAM_CUSTOM
					: FunctionColors.PARAM_DYNAMIC;
		}

		List<Object> objects = variableOffset.getObjects();
		addVariableOffsetElements(opInfo, results, objects, subOpIndex, color);
	}

	private void addVariableOffsetElements(OpInfo opInfo, OpFieldResults results,
			List<?> elements, int subOpIndex, Color color) {

		ColorStyleAttributes attributes = variableRefAttributes.with(color);

		boolean underline = opInfo.isUnderline();
		for (Object element : elements) {

			FontMetrics metrics = getMetrics(attributes.styleAttribute);
			AttributedString as =
				new AttributedString(element.toString(), attributes.colorAttribute,
					metrics, underline, ListingColors.UNDERLINE);
			results.add(
				new OperandFieldElement(as, opInfo.opIndex, subOpIndex, results.characterOffset));
		}
	}

	private void addAutoParameterElement(OpInfo opInfo, OpFieldResults results, Parameter parameter,
			Object opElement, int subOpIndex) {

		Color color = FunctionColors.PARAM_AUTO;
		int variableStyle = variableRefAttributes.styleAttribute;

		boolean underline = opInfo.isUnderline();
		FontMetrics metrics = getMetrics(variableStyle);
		AttributedString as = new AttributedString(opElement.toString(), color, metrics, underline,
			ListingColors.UNDERLINE);
		results.add(
			new OperandFieldElement(as, opInfo.opIndex, subOpIndex, results.characterOffset));
	}

	private OperandFieldElement createSeparatorElement(OpInfo opInfo, OpFieldResults results,
			int subOpIndex, int separatorIndex) {

		String separator = opInfo.getSeparator(separatorIndex);
		if (separator == null) {
			return null;
		}

		if (spaceAfterSeparator) {
			separator += " ";
		}

		AttributedString as = new AttributedString(separator, separatorAttributes.colorAttribute,
			getMetrics(separatorAttributes.styleAttribute));
		return new OperandFieldElement(as, opInfo.opIndex, subOpIndex, results.characterOffset);
	}

	private OperandFieldElement createLeadingSeparatorElement(Instruction instruction) {

		String separator = instruction.getSeparator(0);
		if (separator == null) {
			return null;
		}

		if (spaceAfterSeparator) {
			separator += " ";
		}

		AttributedString as = new AttributedString(separator, separatorAttributes.colorAttribute,
			getMetrics(separatorAttributes.styleAttribute));
		return new OperandFieldElement(as, 0, 0, 0);
	}

	private boolean isUnderlined(CodeUnit codeUnit, int opIndex, boolean primaryReferenceHidden) {
		if (underlineChoice == UNDERLINE_CHOICE.None) {
			return false;
		}

		if (primaryReferenceHidden) {
			return true;
		}

		Reference[] refs = codeUnit.getOperandReferences(opIndex);
		if (underlineChoice == UNDERLINE_CHOICE.Hidden) {
			return containsNonPrimary(refs);
		}

		// this last case assumes (selectedUnderline == ALL)
		return refs.length > 0;
	}

	private boolean containsNonPrimary(Reference[] refs) {
		for (Reference ref : refs) {
			if (!ref.isPrimary()) {
				return true;
			}
		}
		return false;
	}

//==================================================================================================
// Attributes Methods
//==================================================================================================

	private ColorStyleAttributes getOpAttributes(CodeUnit cu, int opIndex, Program p) {

		ColorStyleAttributes attributes = getRefAttributes(cu, opIndex, p);

		if (attributes == null) {
			attributes = scalarAttributes;
		}

		return attributes;
	}

	private ColorStyleAttributes getOpAttributes(OpInfo opInfo, Object opObject) {

		if (opObject instanceof String) {
			return getOpAttributes(opInfo.inst, opInfo.opIndex, opInfo.getProgram());
		}
		if (opObject instanceof Register) {
			return registerAttributes;
		}
		if (opObject instanceof Scalar) {
			return scalarAttributes;
		}
		if (opObject instanceof Address) {
			return addressAttributes;
		}
		if (opObject instanceof Character) {
			return separatorAttributes;
		}
		if (opObject instanceof Equate) {
			Equate equate = (Equate) opObject;
			if (equate.isValidUUID()) {
				return scalarAttributes;
			}
			return badRefAttributes;
		}
		if (opObject instanceof LabelString labelString) {
			return getLabelStringAttributes(labelString, opInfo.inst, opInfo.opIndex);
		}
		return separatorAttributes;
	}

	private ColorStyleAttributes getLabelStringAttributes(LabelString opObject, Instruction inst,
			int opIndex) {

		LabelString label = opObject;
		LabelType labelType = label.getLabelType();
		if (labelType == LabelType.VARIABLE) {
			return variableRefAttributes;
		}
		if (labelType == LabelType.EXTERNAL) {

			Symbol symbol = label.getSymbol();
			ColorStyleAttributes attributes = getExternalSymbolAttributes(symbol);
			if (attributes != null) {
				return attributes;
			}
		}
		return getOpAttributes(inst, opIndex, inst.getProgram());
	}

	private ColorStyleAttributes getExternalSymbolAttributes(Symbol symbol) {
		ColorAndStyle c = inspector.getColorAndStyle(symbol);
		if (c != null) {
			ColorStyleAttributes newAttributes = new ColorStyleAttributes();
			newAttributes.colorAttribute = c.getColor();
			newAttributes.styleAttribute = c.getStyle();
			return newAttributes;
		}
		return null;
	}

	private ColorStyleAttributes getRefAttributes(CodeUnit cu, int opIndex, Program p) {

		ReferenceManager refMgr = p.getReferenceManager();
		Reference[] refs = refMgr.getReferencesFrom(cu.getMinAddress(), opIndex);
		for (Reference ref : refs) {

			// handle external references
			ColorAndStyle c = inspector.getColorAndStyle(p, ref);
			if (c != null) {
				ColorStyleAttributes newAttributes = new ColorStyleAttributes();
				newAttributes.colorAttribute = c.getColor();
				newAttributes.styleAttribute = c.getStyle();
				return newAttributes;
			}
		}

		Reference mr = refMgr.getPrimaryReferenceFrom(cu.getMinAddress(), opIndex);
		if (mr != null) {
			return getAddressAttributes(cu, mr.getToAddress(), opIndex, p);
		}
		return null;
	}

	private boolean isInvalidEquate(Data data) {
		Program program = data.getProgram();
		if (program != null) {
			Scalar scalar = data.getScalar(0);
			Address address = data.getAddress();
			if (scalar == null || address == null) {
				return false;
			}
			Equate equate = program.getEquateTable().getEquate(address, 0, scalar.getValue());
			if (equate != null && !equate.isValidUUID()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Determine the font and color to use to render an operand when that operand is a reference.
	 */
	private ColorStyleAttributes getAddressAttributes(CodeUnit cu, Address destAddr, int opIndex,
			Program p) {

		if (destAddr == null) {
			return separatorAttributes;
		}

		if (destAddr.isMemoryAddress() && !p.getMemory().contains(destAddr)) {
			return badRefAttributes;
		}

		SymbolTable st = p.getSymbolTable();
		ReferenceManager refMgr = p.getReferenceManager();

		Reference ref = refMgr.getReference(cu.getMinAddress(), destAddr, opIndex);
		Symbol sym = st.getSymbol(ref);
		if (sym != null) {
			ColorStyleAttributes newAttributes = new ColorStyleAttributes();
			ColorAndStyle c = inspector.getColorAndStyle(sym);
			newAttributes.colorAttribute = c.getColor();
			newAttributes.styleAttribute = c.getStyle();
			return newAttributes;
		}
		return addressAttributes;
	}

	// Called when the fonts are first initialized or when one of the options
	private void setOptions(Options options) {

		separatorAttributes.colorAttribute = ListingColors.SEPARATOR;
		scalarAttributes.colorAttribute = ListingColors.CONSTANT;
		variableRefAttributes.colorAttribute = FunctionColors.VARIABLE;
		addressAttributes.colorAttribute = ListingColors.ADDRESS;
		badRefAttributes.colorAttribute = ListingColors.REF_BAD;
		registerAttributes.colorAttribute = ListingColors.REGISTER;

		separatorAttributes.styleAttribute =
			options.getInt(OptionsGui.SEPARATOR.getStyleOptionName(), -1);
		scalarAttributes.styleAttribute =
			options.getInt(OptionsGui.CONSTANT.getStyleOptionName(), -1);
		variableRefAttributes.styleAttribute =
			options.getInt(OptionsGui.FUN_VARIABLE.getStyleOptionName(), -1);
		addressAttributes.styleAttribute =
			options.getInt(OptionsGui.ADDRESS.getStyleOptionName(), -1);
		badRefAttributes.styleAttribute =
			options.getInt(OptionsGui.BAD_REF_ADDR.getStyleOptionName(), -1);
		registerAttributes.styleAttribute =
			options.getInt(OptionsGui.REGISTERS.getStyleOptionName(), -1);

	}

	// local dummy container for returning related style information
	private class ColorStyleAttributes {
		private Color colorAttribute;
		private int styleAttribute;

		public ColorStyleAttributes with(Color color) {
			ColorStyleAttributes attrs = new ColorStyleAttributes();
			attrs.styleAttribute = styleAttribute;
			attrs.colorAttribute = color;
			return attrs;
		}
	}

	static class OperandFieldElement extends AbstractTextFieldElement {
		private int operandSubIndex;

		OperandFieldElement(AttributedString as, int operandIndex, int operandSubIndex,
				int characterOffset) {
			super(as, operandIndex, characterOffset);

			this.operandSubIndex = operandSubIndex;
		}

		int getOperandSubIndex() {
			return operandSubIndex;
		}

		int getOperandIndex() {
			return row;
		}

		@Override
		public FieldElement substring(int start, int end) {
			AttributedString as = attributedString.substring(start, end);
			if (as == attributedString) {
				return this;
			}
			return new OperandFieldElement(as, row, operandSubIndex, column + start);
		}

		@Override
		public FieldElement replaceAll(char[] targets, char replacement) {
			return new OperandFieldElement(attributedString.replaceAll(targets, replacement), row,
				operandSubIndex, column);
		}
	}

	/**
	 * Simple object to pass between methods for accumulating results and tracking character offset.
	 */
	private class OpFieldResults {

		private int characterOffset;
		private List<OperandFieldElement> elements = new ArrayList<>();
		private ProxyObj<?> proxy;

		OpFieldResults(ProxyObj<?> proxy) {
			this.proxy = proxy;
		}

		void add(OperandFieldElement element) {
			elements.add(element);
			characterOffset += element.length();
		}

		void addLineBreak() {
			elements.add(LINE_BREAK);
		}

		boolean isEmpty() {
			return elements.isEmpty();
		}

		void resetCharacterOffset() {
			characterOffset = 0;
		}

		ListingTextField createListingTextField(int varWidth) {

			FieldFactory factory = OperandFieldHelper.this;
			if (wrapOnSemicolon) {
				List<FieldElement> lines = breakIntoLines(elements);
				if (lines.size() == 1) {
					return ListingTextField.createSingleLineTextField(factory, proxy,
						lines.get(0), startX + varWidth, width, hlProvider);
				}
				return ListingTextField.createMultilineTextField(factory, proxy, lines, startX,
					width,
					hlProvider);
			}

			return ListingTextField.createSingleLineTextField(factory, proxy,
				new CompositeFieldElement(elements), startX + varWidth, width, hlProvider);

		}
	}

	/**
	 * Simple object to contain data and methods related to the instruction being processed and its
	 * operand representations.
	 */
	private class OpInfo {

		private Instruction inst;
		private int opIndex;

		private OperandRepresentationList opRepList;

		OpInfo(Instruction inst, int opIndex) {
			this.inst = inst;
			this.opIndex = opIndex;
			this.opRepList = codeUnitFormat.getOperandRepresentationList(inst, opIndex);
		}

		boolean isInvalid() {
			return opRepList == null || opRepList.hasError();
		}

		boolean isUnderline() {
			return isUnderlined(inst, opIndex, opRepList.isPrimaryReferenceHidden());
		}

		int getRepCount() {
			return opRepList.size();
		}

		Object getRepElement(int subOpIndex) {
			return opRepList.get(subOpIndex);
		}

		String getRepText() {
			return opRepList != null ? opRepList.toString() : "<UNSUPPORTED>";
		}

		String getSeparator(int separatorIndex) {
			return inst.getSeparator(separatorIndex);
		}

		Program getProgram() {
			return inst.getProgram();
		}
	}
}
