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
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import ghidra.app.util.*;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.StringUtilities;
import ghidra.util.bean.field.AnnotatedTextFieldElement;

/**
  *  Generates End of line comment Fields.
  */
public class EolCommentFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "EOL Comment";
	private final static String GROUP_TITLE = "EOL Comments Field";
	private static final String SEMICOLON_PREFIX = "; ";
	public final static String ENABLE_WORD_WRAP_MSG =
		GROUP_TITLE + Options.DELIMITER + "Enable Word Wrapping";
	public final static String MAX_DISPLAY_LINES_MSG =
		GROUP_TITLE + Options.DELIMITER + "Maximum Lines To Display";
	public final static String ENABLE_SHOW_SEMICOLON_MSG =
		GROUP_TITLE + Options.DELIMITER + "Show Semicolon at Start of Each Line";
	public final static String ENABLE_ALWAYS_SHOW_REPEATABLE_MSG =
		GROUP_TITLE + Options.DELIMITER + "Always Show the Repeatable Comment";
	public final static String ENABLE_ALWAYS_SHOW_REF_REPEATABLE_MSG =
		GROUP_TITLE + Options.DELIMITER + "Always Show the Referenced Repeatable Comments";
	public final static String ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG =
		GROUP_TITLE + Options.DELIMITER + "Always Show the Automatic Comment";
	public static final String USE_ABBREVIATED_AUTOMITIC_COMMENT_MSG =
		GROUP_TITLE + Options.DELIMITER + "Use Abbreviated Automatic Comments";
	public static final String SHOW_FUNCTION_AUTOMITIC_COMMENT_MSG =
		GROUP_TITLE + Options.DELIMITER + "Show Function Reference Automatic Comments";
	public final static String ENABLE_PREPEND_REF_ADDRESS_MSG =
		GROUP_TITLE + Options.DELIMITER + "Prepend the Address to Each Referenced Comment";
	public static final Color DEFAULT_COLOR = Color.BLUE;

	private boolean isWordWrap;
	private int maxDisplayLines;
	private boolean showSemicolon;
	private boolean alwaysShowRepeatable;
	private boolean alwaysShowRefRepeatables;
	private boolean alwaysShowAutomatic;
	private boolean useAbbreviatedAutomatic;
	private boolean showAutomaticFunctions;
	private boolean prependRefAddress;
	private Color repeatableCommentColor;
	private Color automaticCommentColor;
	private Color refRepeatableCommentColor;
	private int repeatableCommentStyle;
	private int automaticCommentStyle;
	private int refRepeatableCommentStyle;

	// The codeUnitFormatOptions is used to monitor "follow pointer..." option to avoid
	// duplication of data within auto-comment.  We don't bother adding a listener
	// to kick the model since this is done by the operand field.
	private BrowserCodeUnitFormatOptions codeUnitFormatOptions;

	/**
	 * Default Constructor
	 */
	public EolCommentFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private EolCommentFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "EOL_Comments_Field");

		fieldOptions.registerOption(MAX_DISPLAY_LINES_MSG, 6, hl,
			"The maximum number of lines used to display the end-of-line comment.");
		fieldOptions.registerOption(ENABLE_WORD_WRAP_MSG, false, hl,
			"Enables word wrapping in the end-of-line comments field.  If word " +
				"wrapping is on, user enter new lines are ignored and the entire comment is" +
				" displayed in paragraph form.  If word wrapping is off, comments are " +
				"displayed in line format however the user entered them.  Lines that are too " +
				"long for the field, are truncated.");

		fieldOptions.registerOption(ENABLE_SHOW_SEMICOLON_MSG, false, hl,
			"Displays a semi-colon before each line in the end-of-line comment. " +
				"This option is ignored if word wrapping is on.");

		fieldOptions.registerOption(ENABLE_ALWAYS_SHOW_REPEATABLE_MSG, false, hl,
			"Displays all referenced repeatable comments even if there is an EOL " +
				"or repeatable comment at the code unit.");

		fieldOptions.registerOption(ENABLE_ALWAYS_SHOW_REF_REPEATABLE_MSG, false, hl,
			"Displays all referenced repeatable comments even if there is an EOL " +
				"or repeatable comment at the code unit.");
		fieldOptions.registerOption(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG, false, hl,
			"Displays an automatic comment whenever one exists instead of only if there " +
				"aren't any EOL or repeatable comments.");
		fieldOptions.registerOption(USE_ABBREVIATED_AUTOMITIC_COMMENT_MSG, true, hl,
			"When showing automatic comments, show the smallest amount of information possible");
		fieldOptions.registerOption(SHOW_FUNCTION_AUTOMITIC_COMMENT_MSG, true, hl,
			"When showing automatic comments, show direct function references");

		fieldOptions.registerOption(ENABLE_PREPEND_REF_ADDRESS_MSG, false, hl,
			"Displays the address before each referenced repeatable comment.");

		maxDisplayLines = fieldOptions.getInt(MAX_DISPLAY_LINES_MSG, 6);
		isWordWrap = fieldOptions.getBoolean(ENABLE_WORD_WRAP_MSG, false);
		repeatableCommentColor =
			displayOptions.getColor(OptionsGui.COMMENT_REPEATABLE.getColorOptionName(),
				OptionsGui.COMMENT_REPEATABLE.getDefaultColor());
		repeatableCommentStyle =
			displayOptions.getInt(OptionsGui.COMMENT_REPEATABLE.getStyleOptionName(), -1);
		automaticCommentColor =
			displayOptions.getColor(OptionsGui.COMMENT_AUTO.getColorOptionName(),
				OptionsGui.COMMENT_AUTO.getDefaultColor());
		automaticCommentStyle =
			displayOptions.getInt(OptionsGui.COMMENT_AUTO.getStyleOptionName(), -1);
		refRepeatableCommentColor =
			displayOptions.getColor(OptionsGui.COMMENT_REF_REPEAT.getColorOptionName(),
				OptionsGui.COMMENT_REF_REPEAT.getDefaultColor());
		refRepeatableCommentStyle =
			displayOptions.getInt(OptionsGui.COMMENT_REF_REPEAT.getStyleOptionName(), -1);
		showSemicolon = fieldOptions.getBoolean(ENABLE_SHOW_SEMICOLON_MSG, false);
		alwaysShowRepeatable = fieldOptions.getBoolean(ENABLE_ALWAYS_SHOW_REPEATABLE_MSG, false);
		alwaysShowRefRepeatables =
			fieldOptions.getBoolean(ENABLE_ALWAYS_SHOW_REF_REPEATABLE_MSG, false);
		alwaysShowAutomatic = fieldOptions.getBoolean(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG, false);
		useAbbreviatedAutomatic =
			fieldOptions.getBoolean(USE_ABBREVIATED_AUTOMITIC_COMMENT_MSG, true);
		showAutomaticFunctions =
			fieldOptions.getBoolean(SHOW_FUNCTION_AUTOMITIC_COMMENT_MSG, true);

		prependRefAddress = fieldOptions.getBoolean(ENABLE_PREPEND_REF_ADDRESS_MSG, false);

		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(hl);

		codeUnitFormatOptions = new BrowserCodeUnitFormatOptions(fieldOptions, true);
	}

	/**
	 * Notification that an option changed.
	 * @param options options object containing the property that changed
	 * @param optionName name of option that changed
	 * @param oldValue old value of the option
	 * @param newValue new value of the option
	 */
	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(MAX_DISPLAY_LINES_MSG)) {
			setMaximumLinesToDisplay(((Integer) newValue).intValue(), options);
		}
		else if (optionName.equals(ENABLE_WORD_WRAP_MSG)) {
			isWordWrap = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ENABLE_SHOW_SEMICOLON_MSG)) {
			showSemicolon = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ENABLE_ALWAYS_SHOW_REPEATABLE_MSG)) {
			alwaysShowRepeatable = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ENABLE_ALWAYS_SHOW_REF_REPEATABLE_MSG)) {
			alwaysShowRefRepeatables = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG)) {
			alwaysShowAutomatic = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(USE_ABBREVIATED_AUTOMITIC_COMMENT_MSG)) {
			useAbbreviatedAutomatic = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ENABLE_PREPEND_REF_ADDRESS_MSG)) {
			prependRefAddress = ((Boolean) newValue).booleanValue();
		}
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		adjustRepeatableDisplayOptions(options, optionName, oldValue, newValue);
		adjustRefRepeatDisplayOptions(options, optionName, oldValue, newValue);
		adjustAutomaticCommentDisplayOptions(options, optionName, oldValue, newValue);
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
	}

	/**
	 * Adjust the Repeatable Comment display options if the associated options changed.
	 *
	 * @param options the Display Options object that changed.
	 * @param optionName the name of the property that changed.
	 * @param oldValue the old value of the property.
	 * @param newValue the new value of the property.
	 */
	private void adjustRepeatableDisplayOptions(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(OptionsGui.COMMENT_REPEATABLE.getColorOptionName())) {
			repeatableCommentColor = (Color) newValue;
		}
		String repeatableStyleName = OptionsGui.COMMENT_REPEATABLE.getStyleOptionName();
		if (optionName.equals(repeatableStyleName)) {
			repeatableCommentStyle = options.getInt(repeatableStyleName, -1);
		}
	}

	/**
	 * Adjust the Referenced Repeatable Comments display options if the associated options changed.
	 *
	 * @param options the Display Options object that changed.
	 * @param optionName the name of the property that changed.
	 * @param oldValue the old value of the property.
	 * @param newValue the new value of the property.
	 */
	private void adjustRefRepeatDisplayOptions(Options options, String optionName, Object oldValue,
			Object newValue) {
		if (optionName.equals(OptionsGui.COMMENT_REF_REPEAT.getColorOptionName())) {
			refRepeatableCommentColor = (Color) newValue;
		}
		String refRepeatStyleName = OptionsGui.COMMENT_REF_REPEAT.getStyleOptionName();
		if (optionName.equals(refRepeatStyleName)) {
			refRepeatableCommentStyle = options.getInt(refRepeatStyleName, -1);
		}
	}

	/**
	 * Adjust the Automatic Comment display options if the associated options changed.
	 * @param options the Display Options object that changed.
	 * @param optionName the name of the property that changed.
	 * @param oldValue the old value of the property.
	 * @param newValue the new value of the property.
	 */
	private void adjustAutomaticCommentDisplayOptions(Options options, String optionName,
			Object oldValue, Object newValue) {
		if (optionName.equals(OptionsGui.COMMENT_AUTO.getColorOptionName())) {
			automaticCommentColor = (Color) newValue;
		}
		String automaticCommentStyleName = OptionsGui.COMMENT_AUTO.getStyleOptionName();
		if (optionName.equals(automaticCommentStyleName)) {
			automaticCommentStyle = options.getInt(automaticCommentStyleName, -1);
		}
	}

	/**
	 * Set the max number of lines to display for EOL comments.
	 */
	private void setMaximumLinesToDisplay(int maxLines, Options options) {
		if (maxLines < 1) {
			maxLines = 1;
			options.setInt(MAX_DISPLAY_LINES_MSG, maxLines);
		}
		maxDisplayLines = maxLines;
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		int x = startX + varWidth;
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		Program program = cu.getProgram();

		//
		// If this code unit is the outside of a data container, then do not display any
		// comments if open.  If this was allowed, then the comment would appear
		// on the outside data container and on the 1st internal member
		//
		if (cu instanceof Data) {
			Data data = (Data) cu;
			if (data.getNumComponents() > 0) {
				boolean isOpen = proxy.getListingLayoutModel().isOpen((Data) proxy.getObject());
				if (isOpen) {
					return null; // avoid double showing
				}
			}
		}

		DisplayableEol displayableEol =
			new DisplayableEol(cu, alwaysShowRepeatable, alwaysShowRefRepeatables,
				alwaysShowAutomatic, codeUnitFormatOptions.followReferencedPointers(),
				maxDisplayLines, useAbbreviatedAutomatic, showAutomaticFunctions);

		List<FieldElement> elementList = new ArrayList<>();

		// This Code Unit's End of Line Comment
		AttributedString myEolPrefixString =
			new AttributedString(SEMICOLON_PREFIX, color, getMetrics(style), false, null);
		String[] eolComments = displayableEol.getEOLComments();
		List<FieldElement> eolFieldElements = convertToFieldElements(program, eolComments,
			myEolPrefixString, showSemicolon, isWordWrap, getNextRow(elementList));
		elementList.addAll(eolFieldElements);

		// This Code Unit's Repeatable Comment
		if (alwaysShowRepeatable || elementList.isEmpty()) {
			AttributedString myRepeatablePrefixString = new AttributedString(SEMICOLON_PREFIX,
				repeatableCommentColor, getMetrics(repeatableCommentStyle), false, null);
			String[] repeatableComments = displayableEol.getRepeatableComments();
			List<FieldElement> repeatableFieldElements =
				convertToFieldElements(program, repeatableComments, myRepeatablePrefixString,
					showSemicolon, isWordWrap, getNextRow(elementList));
			elementList.addAll(repeatableFieldElements);
		}

		// Referenced Repeatable Comments
		if (alwaysShowRefRepeatables || elementList.isEmpty()) {
			AttributedString refRepeatPrefixString = new AttributedString(SEMICOLON_PREFIX,
				refRepeatableCommentColor, getMetrics(refRepeatableCommentStyle), false, null);
			int refRepeatCount = displayableEol.getReferencedRepeatableCommentsCount();
			for (int subTypeIndex = 0; subTypeIndex < refRepeatCount; subTypeIndex++) {
				RefRepeatComment refRepeatComment =
					displayableEol.getReferencedRepeatableComments(subTypeIndex);
				String[] refRepeatComments = refRepeatComment.getCommentLines();
				List<FieldElement> refRepeatFieldElements = convertToRefFieldElements(
					refRepeatComments, program, refRepeatPrefixString, showSemicolon, isWordWrap,
					prependRefAddress, refRepeatComment.getAddress(), getNextRow(elementList));
				elementList.addAll(refRepeatFieldElements);
			}
		}

		// Automatic Comment
		if (alwaysShowAutomatic || elementList.isEmpty()) {
			AttributedString autoCommentPrefixString = new AttributedString(SEMICOLON_PREFIX,
				automaticCommentColor, getMetrics(automaticCommentStyle), false, null);
			String[] autoComment = displayableEol.getAutomaticComment();
			List<FieldElement> autoCommentFieldElements =
				convertToFieldElements(program, autoComment, autoCommentPrefixString, showSemicolon,
					isWordWrap, getNextRow(elementList));
			elementList.addAll(autoCommentFieldElements);
		}

		FieldElement[] fieldElements = elementList.toArray(new FieldElement[elementList.size()]);
		if (fieldElements.length == 0) {
			return null;
		}
		return ListingTextField.createMultilineTextField(this, proxy, fieldElements, x, width,
			maxDisplayLines, hlProvider);
	}

	private int getNextRow(List<FieldElement> elementList) {
		int elementIndex = elementList.size() - 1;
		if (elementIndex >= 0) {
			FieldElement element = elementList.get(elementIndex);
			int length = element.length();
			int charIndex = (length > 0) ? (length - 1) : 0;
			RowColLocation rowCol = element.getDataLocationForCharacterIndex(charIndex);
			return rowCol.row() + 1;
		}
		return 0;
	}

	private List<FieldElement> convertToFieldElements(Program program, String[] comments,
			AttributedString currentPrefixString, boolean showPrefix, boolean wordWrap,
			int nextRow) {

		if (wordWrap) {
			comments = adjustCommentsForWrapping(comments);
		}

		List<FieldElement> fieldElements = new ArrayList<>();
		if (comments.length == 0) {
			return fieldElements;
		}
		for (int rowIndex = 0; rowIndex < comments.length; rowIndex++) {
			int encodedRow = nextRow + rowIndex;
			fieldElements.add(CommentUtils.parseTextForAnnotations(comments[rowIndex], program,
				currentPrefixString, encodedRow));
		}

		if (wordWrap) {
			int lineWidth = showPrefix ? width - currentPrefixString.getStringWidth() : width;
			fieldElements = FieldUtils.wrap(fieldElements, lineWidth);
		}

		if (showPrefix) {
			for (int i = 0; i < fieldElements.size(); i++) {
				RowColLocation startRowCol =
					fieldElements.get(i).getDataLocationForCharacterIndex(0);
				int encodedRow = startRowCol.row();
				int encodedCol = startRowCol.col();
				FieldElement prefix =
					new TextFieldElement(currentPrefixString, encodedRow, encodedCol);
				fieldElements.set(i,
					new CompositeFieldElement(new FieldElement[] { prefix, fieldElements.get(i) }));
			}
		}
		return fieldElements;
	}

	private String[] adjustCommentsForWrapping(String[] comments) {
		List<String> list = new ArrayList<>();
		int lastComment = comments.length - 1;
		for (int i = 0; i < lastComment; i++) {
			String string = comments[i];
			if (!StringUtils.isBlank(string) && !StringUtilities.endsWithWhiteSpace(string)) {
				list.add(string + " ");
			}
			else {
				list.add(string);
			}
		}
		if (lastComment >= 0) {
			list.add(comments[lastComment]);
		}
		comments = list.toArray(new String[list.size()]);
		return comments;
	}

	private List<FieldElement> convertToRefFieldElements(String[] comments, Program program,
			AttributedString currentPrefixString, boolean showPrefix, boolean wordWrap,
			boolean showRefAddress, Address refAddress, int nextRow) {

		if (wordWrap) {
			comments = adjustCommentsForWrapping(comments);
		}

		int numCommentLines = comments.length;
		List<FieldElement> fieldElements = new ArrayList<>();
		if (numCommentLines == 0) {
			return fieldElements;
		}
		for (int rowIndex = 0; rowIndex < numCommentLines; rowIndex++) {
			int encodedRow = nextRow + rowIndex;
			fieldElements.add(CommentUtils.parseTextForAnnotations(comments[rowIndex], program,
				currentPrefixString, encodedRow));
		}
		if (showRefAddress) {
			FieldElement commentElement = fieldElements.get(0);
			// Address
			String refAddrComment = "{@address " + refAddress.toString() + "}";
			RowColLocation startRowCol = commentElement.getDataLocationForCharacterIndex(0);
			int encodedRow = startRowCol.row();
			int encodedCol = startRowCol.col();
			Annotation annotation = new Annotation(refAddrComment, currentPrefixString, program);
			FieldElement addressElement =
				new AnnotatedTextFieldElement(annotation, encodedRow, encodedCol);
			// Space character
			AttributedString spaceStr = new AttributedString(" ", currentPrefixString.getColor(0),
				currentPrefixString.getFontMetrics(0), false, null);
			FieldElement spacerElement = new TextFieldElement(spaceStr, encodedRow, encodedCol);
			fieldElements.add(new CompositeFieldElement(
				new FieldElement[] { addressElement, spacerElement, commentElement }));
		}

		if (wordWrap) {
			int lineWidth = showPrefix ? width - currentPrefixString.getStringWidth() : width;
			fieldElements = FieldUtils.wrap(fieldElements, lineWidth);
		}

		if (showPrefix) {
			for (int i = 0; i < fieldElements.size(); i++) {
				RowColLocation startRowCol =
					fieldElements.get(i).getDataLocationForCharacterIndex(0);
				int encodedRow = startRowCol.row();
				int encodedCol = startRowCol.col();
				FieldElement prefixFieldElement =
					new TextFieldElement(currentPrefixString, encodedRow, encodedCol);
				fieldElements.set(i, new CompositeFieldElement(
					new FieldElement[] { prefixFieldElement, fieldElements.get(i) }));
			}
		}
		return fieldElements;
	}

	/**
	 * @param screenRow the row location for the cursor within the listing field.
	 * @param screenColumn the column location for the cursor within the listing field.
	 * @param bf the listing field.
	 * @return the program location that is equivalent to the cursor location in the field.
	 */
	@Override
	public ProgramLocation getProgramLocation(int screenRow, int screenColumn, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		DisplayableEol displayableEol =
			new DisplayableEol(cu, alwaysShowRepeatable, alwaysShowRefRepeatables,
				alwaysShowAutomatic, codeUnitFormatOptions.followReferencedPointers(),
				maxDisplayLines, useAbbreviatedAutomatic, showAutomaticFunctions);

		// Hold position in connected tool if navigating within semicolon.
		int numLeadColumns = 0;
		if (showSemicolon) {
			numLeadColumns += SEMICOLON_PREFIX.length();
		}
		if (screenColumn < numLeadColumns) {
			screenColumn = 0;
		}

		ListingTextField btf = (ListingTextField) bf;
		RowColLocation rowCol = btf.screenToDataLocation(screenRow, screenColumn);
		int eolRow = rowCol.row();
		int eolColumn = rowCol.col();

		return displayableEol.getLocation(eolRow, eolColumn);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (!((loc instanceof EolCommentFieldLocation) ||
			(loc instanceof RepeatableCommentFieldLocation) ||
			(loc instanceof RefRepeatCommentFieldLocation) ||
			(loc instanceof AutomaticCommentFieldLocation))) {
			return null;
		}

		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		DisplayableEol displayableEol =
			new DisplayableEol((CodeUnit) obj, alwaysShowRepeatable, alwaysShowRefRepeatables,
				alwaysShowAutomatic, codeUnitFormatOptions.followReferencedPointers(),
				maxDisplayLines, useAbbreviatedAutomatic, showAutomaticFunctions);

		ListingTextField btf = (ListingTextField) bf;

		RowColLocation eolRowCol = displayableEol.getRowCol((CommentFieldLocation) loc);
		RowColLocation rcl = btf.dataToScreenLocation(eolRowCol.row(), eolRowCol.col());
		if (!hasSamePath(bf, loc)) {
			return null;
		}
		return new FieldLocation(index, fieldNum, rcl.row(), rcl.col());
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
	public FieldFactory newInstance(FieldFormatModel fieldFormatModel,
			HighlightProvider highlightProvider, ToolOptions newDisplayOptions,
			ToolOptions newFieldOptions) {
		return new EolCommentFieldFactory(fieldFormatModel, highlightProvider, newDisplayOptions,
			newFieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.COMMENT_EOL.getDefaultColor();
	}

	/**
	 * Convert the array of comments to a single string and use the given
	 * separatorChar as the delimiter.
	 *
	 * @param comments array of comments to convert
	 * @param separatorChar character to insert after each element in the comment array
	 * @return the converted string
	 */
	public static String getSingleString(String[] comments, char separatorChar) {
		if (comments.length == 0) {
			return null;
		}
		StringBuffer buf = new StringBuffer(comments[0]);

		for (int i = 1; i < comments.length; i++) {
			buf.append(separatorChar + comments[i]);
		}
		return buf.toString();
	}
}
