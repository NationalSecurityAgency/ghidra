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
import java.util.*;
import java.util.function.Consumer;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.app.util.*;
import ghidra.app.util.viewer.field.ListingColors.CommentColors;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.StringUtilities;
import ghidra.util.bean.field.AnnotatedTextFieldElement;
import ghidra.util.exception.AssertException;
import utility.function.Dummy;

/**
 * Generates End of line comment Fields.
 */
public class EolCommentFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "EOL Comment";
	private static final String GROUP_TITLE = "EOL Comments Field";
	private static final String SEMICOLON_PREFIX = "; ";

	public static final String ENABLE_WORD_WRAP_KEY =
		GROUP_TITLE + Options.DELIMITER + FieldUtils.WORD_WRAP_OPTION_NAME;
	public static final String MAX_DISPLAY_LINES_KEY =
		GROUP_TITLE + Options.DELIMITER + "Maximum Lines";
	public static final String ENABLE_SHOW_SEMICOLON_KEY =
		GROUP_TITLE + Options.DELIMITER + "Prepend Semicolon";
	public static final String ENABLE_PREPEND_REF_ADDRESS_KEY =
		GROUP_TITLE + Options.DELIMITER + "Prepend Address to References";
	public static final String EXTRA_COMMENT_KEY =
		GROUP_TITLE + Options.DELIMITER + "Auto Comments";

	public static final Color DEFAULT_COLOR = Palette.BLUE;

	private boolean isWordWrap;
	private int maxDisplayLines;
	private boolean showSemicolon;
	private boolean prependRefAddress;
	private int repeatableCommentStyle;
	private int automaticCommentStyle;
	private int refRepeatableCommentStyle;

	private EolExtraCommentsOption extraCommentsOption = new EolExtraCommentsOption();

	// The codeUnitFormatOptions is used to monitor "follow pointer..." option to avoid duplication
	// of data within auto-comment.  We don't bother adding a listener to kick the model since this
	// is done by the operand field.
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
	private EolCommentFieldFactory(FieldFormatModel model, ListingHighlightProvider hlProvider,
			ToolOptions displayOptions, ToolOptions fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		HelpLocation hl = new HelpLocation("CodeBrowserPlugin", "EOL_Comments_Field");

		fieldOptions.registerOption(MAX_DISPLAY_LINES_KEY, 6, hl,
			"The maximum number of lines used to display the end-of-line comment.");
		fieldOptions.registerOption(ENABLE_WORD_WRAP_KEY, false, hl,
			FieldUtils.WORD_WRAP_OPTION_DESCRIPTION);

		fieldOptions.registerOption(ENABLE_SHOW_SEMICOLON_KEY, false, hl,
			"Displays a semi-colon before each line in the end-of-line comment. " +
				"This option is ignored if word wrapping is on.");

		fieldOptions.registerOption(ENABLE_PREPEND_REF_ADDRESS_KEY, false, hl,
			"Displays the address before each referenced repeatable comment.");

		maxDisplayLines = fieldOptions.getInt(MAX_DISPLAY_LINES_KEY, 6);
		isWordWrap = fieldOptions.getBoolean(ENABLE_WORD_WRAP_KEY, false);
		repeatableCommentStyle =
			displayOptions.getInt(OptionsGui.COMMENT_REPEATABLE.getStyleOptionName(), -1);
		automaticCommentStyle =
			displayOptions.getInt(OptionsGui.COMMENT_AUTO.getStyleOptionName(), -1);
		refRepeatableCommentStyle =
			displayOptions.getInt(OptionsGui.COMMENT_REF_REPEAT.getStyleOptionName(), -1);
		showSemicolon = fieldOptions.getBoolean(ENABLE_SHOW_SEMICOLON_KEY, false);
		prependRefAddress = fieldOptions.getBoolean(ENABLE_PREPEND_REF_ADDRESS_KEY, false);

		fieldOptions.getOptions(GROUP_TITLE).setOptionsHelpLocation(hl);

		codeUnitFormatOptions = new BrowserCodeUnitFormatOptions(fieldOptions, true);

		setupAutoCommentOptions(fieldOptions, hl);
	}

	private void setupAutoCommentOptions(Options fieldOptions, HelpLocation hl) {
		fieldOptions.registerOption(EXTRA_COMMENT_KEY, OptionType.CUSTOM_TYPE,
			new EolExtraCommentsOption(), hl, "The group of auto comment options",
			() -> new EolExtraCommentsPropertyEditor());
		CustomOption customOption = fieldOptions.getCustomOption(EXTRA_COMMENT_KEY, null);

		if (!(customOption instanceof EolExtraCommentsOption)) {
			throw new AssertException("Someone set an option for " + EXTRA_COMMENT_KEY +
				" that is not the expected " + EolExtraCommentsOption.class.getName() + " type.");
		}

		extraCommentsOption = (EolExtraCommentsOption) customOption;
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
		if (optionName.equals(MAX_DISPLAY_LINES_KEY)) {
			setMaximumLinesToDisplay(((Integer) newValue).intValue(), options);
		}
		else if (optionName.equals(ENABLE_WORD_WRAP_KEY)) {
			isWordWrap = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ENABLE_SHOW_SEMICOLON_KEY)) {
			showSemicolon = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(EXTRA_COMMENT_KEY)) {
			extraCommentsOption = (EolExtraCommentsOption) newValue;
		}
		else if (optionName.equals(ENABLE_PREPEND_REF_ADDRESS_KEY)) {
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
			options.setInt(MAX_DISPLAY_LINES_KEY, maxLines);
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
		if (isOpenData(cu, proxy)) {
			return null;
		}

		EolComments comments = new EolComments(cu, codeUnitFormatOptions.followReferencedPointers(),
			maxDisplayLines, extraCommentsOption);

		// This Code Unit's End of Line Comment
		List<FieldElement> elementList = new ArrayList<>();
		AttributedString prefix = createPrefix(CommentStyle.EOL);
		List<String> eols = comments.getEOLComments();
		List<FieldElement> eolElements = convertToFieldElements(program, eols, prefix, 0, true);
		elementList.addAll(eolElements);

		/*
		 	 This section describes the various EOL comment types that may appear.  The user can 
		 	 toggle which types are enabled.  The comments are displayed in the order listed below.
		 	 
		 	 EOL Types:
		 	 
		 	 	- EOL			- user end of line comment
		 	 	
		 	 	- Repeatable 	- user repeatable source comment *at the code unit* 
		 	 	- Ref Repeatable- for every reference *from a code unit*, show the target: 
		 	 					  	- address repeatable, 
		 	 					  	- function repeatable, 
		 	 					  	- code unit repeatable  
		 	 					  	
		 	 	- Auto			- fabricated reference preview: 
		 	 						- function, 
		 	 						- indirect data pointer, 
		 	 						- direct data access preview
		 	 					*depending on the options, this typically do not appear when 
		 	 					 repeatable comments exist
		 	 					 
		 	 	- Offcut 		- comments at addresses inside of a code unit
		 */

		if (comments.isShowingRepeatables()) {
			prefix = createPrefix(CommentStyle.REPEATABLE);
			int row = getNextRow(elementList);
			List<String> repeatables = comments.getRepeatableComments();
			List<FieldElement> elements =
				convertToFieldElements(program, repeatables, prefix, row, true);
			elementList.addAll(elements);
		}

		if (comments.isShowingRefRepeatables()) {

			AttributedString refPrefix = createPrefix(CommentStyle.REF_REPEATABLE);
			List<RefRepeatComment> refRepeatables = comments.getReferencedRepeatableComments();
			for (RefRepeatComment comment : refRepeatables) {

				int row = getNextRow(elementList);
				String[] lines = comment.getCommentLines();
				Address refAddress = comment.getAddress();
				List<String> linesList = Arrays.asList(lines);

				Consumer<List<FieldElement>> decorator = elements -> {
					prependRefAddress(program, refPrefix, refAddress, elements);
				};

				List<FieldElement> elements =
					convertToFieldElements(program, linesList, decorator, prefix, row, true);
				elementList.addAll(elements);
			}
		}

		if (comments.isShowingAutoComments()) {
			prefix = createPrefix(CommentStyle.AUTO);
			int row = getNextRow(elementList);
			List<String> autos = comments.getAutomaticComment();

			// Note: we pass 'false' for allowing annotations so that the user will see the raw data
			// and not an interpreted annotation.
			List<FieldElement> elements =
				convertToFieldElements(program, autos, prefix, row, false);
			elementList.addAll(elements);
		}

		if (comments.isShowingOffcutComments()) {
			prefix = createPrefix(CommentStyle.OFFCUT);
			int row = getNextRow(elementList);
			List<String> offcuts = comments.getOffcutEolComments();
			List<FieldElement> elements =
				convertToFieldElements(program, offcuts, prefix, row, true);
			elementList.addAll(elements);
		}

		if (elementList.isEmpty()) {
			return null;
		}
		return ListingTextField.createMultilineTextField(this, proxy, elementList, x, width,
			maxDisplayLines, hlProvider);
	}

	private boolean isOpenData(CodeUnit cu, ProxyObj<?> proxy) {
		if (cu instanceof Data data) {
			if (data.getNumComponents() > 0) {
				ListingModel listingModel = proxy.getListingLayoutModel();
				if (listingModel.isOpen(data)) {
					return true;
				}
			}
		}
		return false;
	}

	private AttributedString createPrefix(CommentStyle commentStyle) {
		if (commentStyle == CommentStyle.EOL) {
			return new AttributedString(SEMICOLON_PREFIX, CommentColors.EOL, getMetrics(style),
				false, null);
		}
		if (commentStyle == CommentStyle.REPEATABLE) {
			return new AttributedString(SEMICOLON_PREFIX, CommentColors.REPEATABLE,
				getMetrics(repeatableCommentStyle), false, null);
		}
		if (commentStyle == CommentStyle.REF_REPEATABLE) {
			return new AttributedString(SEMICOLON_PREFIX, CommentColors.REF_REPEATABLE,
				getMetrics(refRepeatableCommentStyle), false, null);
		}
		if (commentStyle == CommentStyle.AUTO) {
			return new AttributedString(SEMICOLON_PREFIX, CommentColors.AUTO,
				getMetrics(automaticCommentStyle), false, null);
		}
		if (commentStyle == CommentStyle.OFFCUT) {
			return new AttributedString(SEMICOLON_PREFIX, CommentColors.OFFCUT,
				getMetrics(style), false, null);
		}

		throw new AssertException("Unexected comment style: " + commentStyle);
	}

	private enum CommentStyle {
		EOL, REPEATABLE, REF_REPEATABLE, AUTO, OFFCUT;
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

	private List<FieldElement> convertToFieldElements(Program program, List<String> comments,
			AttributedString prefix, int row, boolean allowAnnotations) {

		Consumer<List<FieldElement>> decorator = Dummy.consumer(); // no decorations by default 
		return convertToFieldElements(program, comments, decorator, prefix, row, allowAnnotations);
	}

	private List<FieldElement> convertToFieldElements(Program program, List<String> comments,
			Consumer<List<FieldElement>> decorator, AttributedString prefix, int row,
			boolean allowAnnotations) {

		List<FieldElement> fieldElements = new ArrayList<>();
		if (comments.isEmpty()) {
			return fieldElements;
		}

		for (int commentRow = 0; commentRow < comments.size(); commentRow++) {
			int encodedRow = row + commentRow;
			String commentText = comments.get(commentRow);
			FieldElement element =
				createCommentField(commentText, prefix, program, encodedRow, allowAnnotations);
			fieldElements.add(element);
		}

		decorator.accept(fieldElements);

		if (isWordWrap) {
			int lineWidth = showSemicolon ? width - prefix.getStringWidth() : width;
			fieldElements = FieldUtils.wrap(fieldElements, lineWidth);
		}

		if (showSemicolon) {
			for (int i = 0; i < fieldElements.size(); i++) {
				RowColLocation startRowCol =
					fieldElements.get(i).getDataLocationForCharacterIndex(0);
				int encodedRow = startRowCol.row();
				int encodedCol = startRowCol.col();
				FieldElement prefixElement = new TextFieldElement(prefix, encodedRow, encodedCol);
				fieldElements.set(i,
					new CompositeFieldElement(List.of(prefixElement, fieldElements.get(i))));
			}
		}
		return fieldElements;
	}

	private FieldElement createCommentField(String commentText, AttributedString prototype,
			Program program, int row, boolean allowAnnotations) {

		if (allowAnnotations) {
			return CommentUtils.parseTextForAnnotations(commentText, program, prototype, row);
		}

		String text = StringUtilities.convertTabsToSpaces(commentText);
		AttributedString as = new AttributedString(text, prototype.getColor(0),
			prototype.getFontMetrics(0), false, null);
		return new TextFieldElement(as, row, 0);
	}

	private void prependRefAddress(Program program, AttributedString prefix, Address refAddress,
			List<FieldElement> fieldElements) {

		if (!prependRefAddress) {
			return;
		}

		FieldElement commentElement = fieldElements.get(0);

		// Address
		String refAddrComment = "{@address " + refAddress.toString() + "}";
		RowColLocation startRowCol = commentElement.getDataLocationForCharacterIndex(0);
		int encodedRow = startRowCol.row();
		int encodedCol = startRowCol.col();
		Annotation annotation = new Annotation(refAddrComment, program);
		FieldElement addressElement =
			new AnnotatedTextFieldElement(annotation, prefix, program, encodedRow, encodedCol);

		// Space character
		AttributedString spaceStr = new AttributedString(" ", prefix.getColor(0),
			prefix.getFontMetrics(0), false, null);
		FieldElement spacerElement = new TextFieldElement(spaceStr, encodedRow, encodedCol);
		fieldElements.set(0, new CompositeFieldElement(
			new FieldElement[] { addressElement, spacerElement, commentElement }));
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
		EolComments displayableEol = new EolComments(cu,
			codeUnitFormatOptions.followReferencedPointers(), maxDisplayLines, extraCommentsOption);

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

		EolComments displayableEol = new EolComments((CodeUnit) obj,
			codeUnitFormatOptions.followReferencedPointers(), maxDisplayLines, extraCommentsOption);

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
			ListingHighlightProvider highlightProvider, ToolOptions newDisplayOptions,
			ToolOptions newFieldOptions) {
		return new EolCommentFieldFactory(fieldFormatModel, highlightProvider, newDisplayOptions,
			newFieldOptions);
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
