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
import ghidra.app.util.HelpTopics;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.DataProxy;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

/**
 * Class for showing plate comments
 */
public class PlateFieldFactory extends FieldFactory {

	private static final String EMPTY_STRING = "";
	public static final String FIELD_NAME = "Plate Comment";
	public static final Color DEFAULT_COLOR = Color.BLUE;
	private final static String FIELD_GROUP_TITLE = "Plate Comments Field";
	public final static String ENABLE_WORD_WRAP_MSG =
		FIELD_GROUP_TITLE + Options.DELIMITER + "Enable Word Wrapping";

	/**
	 * This is the length of the padding, which is a '*' and a space on each side
	 */
	private static final int CONTENT_PADDING = 4;
	private static final String ELLIPSIS = "...";
	final static String FUNCTION_PLATE_COMMENT = " FUNCTION";
	final static String THUNK_FUNCTION_PLATE_COMMENT = " THUNK FUNCTION";
	final static String POINTER_TO_EXTERNAL_FUNCTION_COMMENT = " POINTER to EXTERNAL FUNCTION";
	final static String POINTER_TO_NONEXTERNAL_FUNCTION_COMMENT = " POINTER to FUNCTION";
	final static String CASE_PLATE_COMMENT = " CASE";
	final static String EXT_ENTRY_PLATE_COMMENT = " EXTERNAL ENTRY";
	final static String DEAD_CODE_PLATE_COMMENT = " DEAD";
	final static String SUBROUTINE_PLATE_COMMENT = " SUBROUTINE";
	final static String DEFAULT_PLATE_COMMENT = "  ";

	final static String GROUP_TITLE = "Format Code";
	final static String SHOW_SUBROUTINE_PLATES_OPTION =
		GROUP_TITLE + Options.DELIMITER + "  Show Subroutine Plates";
	final static String SHOW_FUNCTION_PLATES_OPTION =
		GROUP_TITLE + Options.DELIMITER + "  Show Function Plates";
	final static String SHOW_TRANSITION_PLATES_OPTION =
		GROUP_TITLE + Options.DELIMITER + "  Show Transition Plates";
	final static String SHOW_EXT_ENTRY_PLATES_OPTION =
		GROUP_TITLE + Options.DELIMITER + "  Show External Entry Plates";

	final static String LINES_BEFORE_FUNCTIONS_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Lines Before Functions";
	final static String LINES_BEFORE_LABELS_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Lines Before Labels";
	final static String LINES_BEFORE_PLATES_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Lines Before Plates";

	private boolean initialized;

	private String stars = EMPTY_STRING;
	private boolean showFunctionPlates;
	private boolean showSubroutinePlates;
	private boolean showTransitionPlates;
	private boolean showExternalPlates;
//    private boolean showCasePlates;

	private boolean showExternalFunctionPointerPlates;
	private boolean showNonExternalFunctionPointerPlates;

	private int nLinesBeforeFunctions;
	private int nLinesBeforeLabels;
	private int nLinesBeforePlates;
	private boolean isWordWrap;

	/**
	 * Constructor
	 */
	public PlateFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private PlateFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);
		init(fieldOptions);

//		showCasePlates = fieldOptions.getBoolean(name, SHOW_CASE_PLATES_OPTION, false);
		isWordWrap = fieldOptions.getBoolean(ENABLE_WORD_WRAP_MSG, false);
		showExternalPlates = fieldOptions.getBoolean(SHOW_EXT_ENTRY_PLATES_OPTION, false);
		showFunctionPlates = fieldOptions.getBoolean(SHOW_FUNCTION_PLATES_OPTION, true);
		showSubroutinePlates = fieldOptions.getBoolean(SHOW_SUBROUTINE_PLATES_OPTION, true);
		showTransitionPlates = fieldOptions.getBoolean(SHOW_TRANSITION_PLATES_OPTION, false);
		nLinesBeforeFunctions = fieldOptions.getInt(LINES_BEFORE_FUNCTIONS_OPTION, 0);
		nLinesBeforeLabels = fieldOptions.getInt(LINES_BEFORE_LABELS_OPTION, 1);
		nLinesBeforePlates = fieldOptions.getInt(LINES_BEFORE_PLATES_OPTION, 0);

		showExternalFunctionPointerPlates = fieldOptions
				.getBoolean(ListingModel.DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME, true);
		showNonExternalFunctionPointerPlates = fieldOptions
				.getBoolean(ListingModel.DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME, false);

	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		if (!enabled) {
			return null;
		}

		CodeUnit cu = (CodeUnit) proxy.getObject();
		boolean isClipped = false;
		List<FieldElement> elements = new ArrayList<>();
		String commentText = getCommentText(cu);
		if (StringUtils.isBlank(commentText)) {
			getDefaultFieldElements(cu, elements);
		}
		else {
			isClipped = getFormattedFieldElements(cu, elements);
		}

		if (elements.isEmpty()) {
			return null; // no real or default comments
		}

		if (isNestedDataAtSameAddressAsParent(proxy)) {
			// This is data at the same address as the parent, which happens with the first
			// element in a structure.  We do not want to the plate comment here, but only at the
			// parent topmost address.
			return null;
		}

		PlateFieldTextField textField =
			new PlateFieldTextField(elements, this, proxy, startX, width, commentText, isClipped);
		return new PlateListingTextField(proxy, textField);
	}

	private boolean getFormattedFieldElements(CodeUnit cu, List<FieldElement> elements) {

		int numberBlankLines = getNumberBlankLines(cu, true);

		addBlankLines(elements, numberBlankLines, cu);

		String[] comments = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
		return generateFormattedPlateComment(elements, comments, cu.getProgram());
	}

	private void getDefaultFieldElements(CodeUnit cu, List<FieldElement> elements) {

		int numberBlankLines = getNumberBlankLines(cu, true);
		addBlankLines(elements, numberBlankLines, cu);

		String defaultComment = getDefaultComment(cu);
		if (defaultComment != null) {
			generateDefaultPlate(elements, defaultComment);
		}
	}

	private boolean isNestedDataAtSameAddressAsParent(ProxyObj<?> proxy) {
		if (proxy instanceof DataProxy) {
			DataProxy dp = (DataProxy) proxy;
			Data data = dp.getObject();
			int[] cpath = data.getComponentPath();
			if (cpath.length > 0) {
				if (cpath[cpath.length - 1] == 0) {
					return true;
				}
			}
		}
		return false;
	}

	private String getCommentText(CodeUnit cu) {
		String[] comments = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
		if (comments == null) {
			return null;
		}

		StringBuilder buffy = new StringBuilder();
		for (String comment : comments) {
			if (buffy.length() != 0) {
				buffy.append('\n');
			}
			buffy.append(comment);
		}
		return buffy.toString();
	}

	/*
	 * Creates desired FieldElements and puts them in the given list.  Returns true if any of the
	 * data is clipped because it is too long to display.
	 */
	private boolean generateFormattedPlateComment(List<FieldElement> elements, String[] comments,
			Program p) {
		if (comments == null || comments.length == 0) {
			return false;
		}

		AttributedString prototype = new AttributedString(EMPTY_STRING, color, getMetrics());

		AttributedString asteriscs = getStarsString();
		int row = elements.size();

		// add top border
		elements.add(new TextFieldElement(asteriscs, row++, 0));

		int commentsStart = row;
		for (String c : comments) {
			FieldElement element = CommentUtils.parseTextForAnnotations(c, p, prototype, row++);
			elements.add(element);
		}

		if (isWordWrap) {
			elements = FieldUtils.wordWrapList(new CompositeFieldElement(elements), width);
		}

		boolean isClipped = addSideBorders(elements, commentsStart);

		// add bottom border
		elements.add(new TextFieldElement(asteriscs, row++, 0));

		return isClipped;
	}

	/**
	 * Generate a text line for the plate text.
	 * Text will be left justified between two '*' and padded based upon the
	 * available field width.
	 * @param elements the field elements that may get updated
	 * @param commentsStart the start index of comment elements in the element list
	 * @return formatted plate text line
	 */
	private boolean addSideBorders(List<FieldElement> elements, int commentsStart) {
		boolean isClipped = false;

		// If there is only a single line comment, then center it
		int n = elements.size() - commentsStart;
		if (n == 1) {
			FieldElement element = elements.get(0);
			if (element.length() > 1 && element.charAt(0) == ' ') { // not sure why the space matters
				FieldElementResult result = addSideBorder(element.substring(1), 1, true);
				isClipped = result.isClipped();
				elements.set(0, result.getFieldElement());
				return isClipped;
			}
		}

		for (int i = commentsStart; i < elements.size(); i++) {
			FieldElementResult result = addSideBorder(elements.get(i), i, false);
			isClipped |= result.isClipped();
			elements.set(i, result.getFieldElement());
		}
		return isClipped;
	}

	private FieldElementResult addSideBorder(FieldElement element, int row, boolean center) {

		int ellipsisLength = 0;
		int availableWidth = stars.length() - CONTENT_PADDING;
		String ellipsisText = EMPTY_STRING;
		if (element.length() > availableWidth) {
			// not enough room; clip the text and add ellipses
			ellipsisText = ELLIPSIS;
			ellipsisLength = ELLIPSIS.length();
			availableWidth = stars.length() - CONTENT_PADDING - ellipsisLength;
			element = element.substring(0, availableWidth); // clip
		}

		int charWidth = getMetrics().charWidth(' ');
		int paddingWidth = (CONTENT_PADDING + ellipsisLength) * charWidth;
		int textWidth = paddingWidth + element.getStringWidth();
		int totalPadding = (width - textWidth) / charWidth;
		int prePadding = center ? totalPadding / 2 : 0;
		int postPadding = center ? (totalPadding + 1) / 2 : totalPadding;

		StringBuilder buffy = new StringBuilder();
		buffy.append('*').append(' ');
		addPadding(buffy, prePadding);

		FieldElement prefix = new TextFieldElement(
			new AttributedString(buffy.toString(), color, getMetrics()), row, 0);

		FieldElement ellipsis =
			new TextFieldElement(new AttributedString(ellipsisText, color, getMetrics()), row,
				prefix.length() + element.length());

		buffy.setLength(0);
		addPadding(buffy, postPadding);
		buffy.append(' ').append('*');

		FieldElement suffix =
			new TextFieldElement(new AttributedString(buffy.toString(), color, getMetrics()), row,
				prefix.length() + element.length() + ellipsis.length());

		return new FieldElementResult(
			new CompositeFieldElement(new FieldElement[] { prefix, element, ellipsis, suffix }),
			ellipsisLength > 0);
	}

	private void addPadding(StringBuilder buf, int count) {
		for (int i = 0; i < count; i++) {
			buf.append(' ');
		}
	}

	private void addBlankLines(List<FieldElement> elements, int numberBlankLines, CodeUnit cu) {
		AttributedString prototype = new AttributedString(EMPTY_STRING, color, getMetrics());
		for (int row = 0; row < numberBlankLines; row++) {
			elements.add(new TextFieldElement(prototype, row, 0));
		}
	}

	private int getNumberBlankLines(CodeUnit cu, boolean hasPlate) {
		if (cu.getProgram().getListing().getFunctionAt(cu.getMinAddress()) != null) {
			if (nLinesBeforeFunctions != 0) {
				return nLinesBeforeFunctions;
			}
		}

		if (hasPlate && nLinesBeforePlates != 0) {
			return nLinesBeforePlates;
		}

		if (cu.getLabel() != null) {
			return nLinesBeforeLabels;
		}

		return 0;
	}

	private void generateDefaultPlate(List<FieldElement> elements, String defaultComment) {
		if (defaultComment == null) {
			return;
		}

		AttributedString asteriscs = getStarsString();
		int row = elements.size();

		// top border
		elements.add(0, new TextFieldElement(asteriscs, row++, 0));

		AttributedString as = new AttributedString(defaultComment, color, getMetrics());
		elements.add(new TextFieldElement(as, row++, 0));
		addSideBorders(elements, 1);

		// bottom border
		elements.add(new TextFieldElement(asteriscs, row++, 0));
	}

	private String getDefaultComment(CodeUnit cu) {

		if (showFunctionPlates) {
			Function function = cu.getProgram().getListing().getFunctionAt(cu.getMinAddress());
			if (function != null) {
				return function.isThunk() ? THUNK_FUNCTION_PLATE_COMMENT : FUNCTION_PLATE_COMMENT;
			}
		}

		if (showExternalPlates && isExternalEntry(cu)) {
			return EXT_ENTRY_PLATE_COMMENT;
		}

		if (showSubroutinePlates && hasCallReferences(cu)) {
			return SUBROUTINE_PLATE_COMMENT;
		}

		if (showTransitionPlates) {
			if (isDeadCode(cu)) {
				return DEAD_CODE_PLATE_COMMENT;
			}
			if (isTransitionCode(cu)) {
				return DEFAULT_PLATE_COMMENT;
			}
		}

		if (showFunctionPlates && cu instanceof Data && ((Data) cu).isPointer()) {
			Reference ref = cu.getPrimaryReference(0);
			if (ref != null) {
				Symbol s = cu.getProgram().getSymbolTable().getPrimarySymbol(ref.getToAddress());
				if (s != null && s.getSymbolType() == SymbolType.FUNCTION) {
					if (showExternalFunctionPointerPlates && s.isExternal()) {
						return POINTER_TO_EXTERNAL_FUNCTION_COMMENT;
					}
					if (showNonExternalFunctionPointerPlates && !s.isExternal()) {
						return POINTER_TO_NONEXTERNAL_FUNCTION_COMMENT;
					}
				}
			}
		}

		return null;
	}

	private boolean isExternalEntry(CodeUnit cu) {
		return cu.getProgram().getSymbolTable().isExternalEntryPoint(cu.getMinAddress());
	}

	private boolean hasCallReferences(CodeUnit cu) {
		Program program = cu.getProgram();
		ReferenceIterator iter = program.getReferenceManager().getReferencesTo(cu.getMinAddress());
		int count = 0;
		while (iter.hasNext() && ++count < 10) { // only check the first 10, it should hit by then
			Reference ref = iter.next();
			RefType refType = ref.getReferenceType();

			if (refType == RefType.CONDITIONAL_CALL || refType == RefType.UNCONDITIONAL_CALL) {
				return true;
			}
		}
		return false;
	}

	private AttributedString getStarsString() {
		String asteriscs = getStars();
		return new AttributedString(asteriscs, color, getMetrics());
	}

	/**
	 * Get a stars string based upon the available width.
	 * @return string of '*'s
	 */
	private String getStars() {
		int starWidth = getMetrics().charWidth('*');
		int n = width / starWidth;

		if (stars.length() != n) {
			StringBuilder buf = new StringBuilder();
			for (int i = 0; i < n; i++) {
				buf.append('*');
			}
			stars = buf.toString();
		}
		return stars;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField listingField) {
		Object proxyObject = listingField.getProxy().getObject();
		// if on a function, get the code unit there.
		if (proxyObject instanceof Function) {
			Function func = (Function) proxyObject;
			Listing listing = func.getProgram().getListing();
			proxyObject = listing.getCodeUnitAt(func.getEntryPoint());
		}
		if (!(proxyObject instanceof CodeUnit)) {
			return null;
		}

		int[] cpath = null;
		if (proxyObject instanceof Data) {
			cpath = ((Data) proxyObject).getComponentPath();
		}

		CodeUnit cu = (CodeUnit) proxyObject;
		String[] comments = cu.getCommentAsArray(CodeUnit.PLATE_COMMENT);
		RowColLocation dataLocation =
			((ListingTextField) listingField).screenToDataLocation(row, col);

		//
		// The 'row' value includes blank lines and header decoration lines.  The 'commentRow' used
		// below is the index into the list of comments.  Calculate the comment beginning by
		// removing the non-comment lines.
		//
		int fillerLineCount = getNumberOfLeadingFillerLines(listingField);
		int commentRow = row - fillerLineCount;
		if (commentRow >= comments.length || commentRow < 0) {
			commentRow = -1; // clicked above the comment or the bottom decoration line
		}

		return new PlateFieldLocation(cu.getProgram(), ((CodeUnit) proxyObject).getMinAddress(),
			cpath, commentRow, dataLocation.col(), comments, commentRow);
	}

	private int getNumberOfLeadingFillerLines(ListingField listingField) {
		if (!(listingField instanceof PlateListingTextField)) {
			return 0;
		}

		PlateFieldTextField plateField = ((PlateListingTextField) listingField).getPlateTextField();
		return plateField.getLeadingFillerLineCount();
	}

	@Override
	public FieldLocation getFieldLocation(ListingField listingField, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {

		if (!(programLoc instanceof CommentFieldLocation)) {
			return null;
		}

		CommentFieldLocation commentLocation = (CommentFieldLocation) programLoc;
		if (commentLocation.getCommentType() != CodeUnit.PLATE_COMMENT) {
			return null;
		}

		// location was not generated by the browser, so create the
		// appropriate field location
		Object obj = listingField.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}

		/*
		 	Calculate the data row using the model row provided in the location, along with
		 	compensating for any spacing and plate comment decorations.   For example, for this
		 	comment,
		 	
		 		This is line one
		 		This is line two
		 		
		 	the plate comment may look like this
		 	
		 		(blank line)
		 		****************************
		 		* This is line one
		 		* This is line two
		 		*****************************
		 */

		CodeUnit cu = (CodeUnit) obj;
		String commentText = getCommentText(cu);
		boolean hasComment = true;
		if (StringUtils.isBlank(commentText)) {
			String defaultComment = getDefaultComment(cu);
			if (defaultComment == null) {
				hasComment = false;
			}
		}

		int commentRow = commentLocation.getRow();
		int numberBlankLines = getNumberBlankLines(cu, hasComment);
		int headerCount = hasComment ? 1 : 0;
		int dataRow = commentRow + numberBlankLines + headerCount;

		ListingTextField listingTextField = (ListingTextField) listingField;
		RowColLocation location = listingTextField.dataToScreenLocation(dataRow,
			commentLocation.getCharOffset());
		return new FieldLocation(index, fieldNum, location.row(), location.col());
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		if (!CodeUnit.class.isAssignableFrom(proxyObjectClass)) {
			return false;
		}

		// some users like the look of plate comments and would like them in many places
		return (category == FieldFormatModel.PLATE || category == FieldFormatModel.OPEN_DATA ||
			category == FieldFormatModel.INSTRUCTION_OR_DATA);
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel formatModel, HighlightProvider hsProvider,
			ToolOptions toolOptions, ToolOptions fieldOptions) {
		return new PlateFieldFactory(formatModel, hsProvider, toolOptions, fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.COMMENT_PLATE.getDefaultColor();
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(SHOW_EXT_ENTRY_PLATES_OPTION)) {
			showExternalPlates = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(SHOW_FUNCTION_PLATES_OPTION)) {
			showFunctionPlates = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(SHOW_SUBROUTINE_PLATES_OPTION)) {
			showSubroutinePlates = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(SHOW_TRANSITION_PLATES_OPTION)) {
			showTransitionPlates = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(LINES_BEFORE_FUNCTIONS_OPTION)) {
			nLinesBeforeFunctions = ((Integer) newValue).intValue();
			if (nLinesBeforeFunctions < 0) {
				nLinesBeforeFunctions = 0;
			}
			model.update();
		}
		else if (optionName.equals(LINES_BEFORE_LABELS_OPTION)) {
			nLinesBeforeLabels = ((Integer) newValue).intValue();
			if (nLinesBeforeLabels < 0) {
				nLinesBeforeLabels = 0;
			}
			model.update();
		}
		else if (optionName.equals(LINES_BEFORE_PLATES_OPTION)) {
			nLinesBeforePlates = ((Integer) newValue).intValue();
			if (nLinesBeforePlates < 0) {
				nLinesBeforePlates = 0;
			}
			model.update();
		}
		else if (optionName.equals(ENABLE_WORD_WRAP_MSG)) {
			isWordWrap = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ListingModel.DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME)) {
			showExternalFunctionPointerPlates = (Boolean) newValue;
		}
		else if (optionName.equals(ListingModel.DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME)) {
			showNonExternalFunctionPointerPlates = (Boolean) newValue;
		}
	}

	private boolean isDeadCode(CodeUnit cu) {

		if (!(cu instanceof Instruction)) {
			return false;
		}

		if (isFalledTo(cu)) {
			return false;
		}

		if (hasReferencesTo(cu)) {
			return false;
		}

		return !((Instruction) cu).isInDelaySlot();
	}

	private boolean isFalledTo(CodeUnit cu) {
		CodeUnit prev = getPreviousCodeUnit(cu);
		return (prev instanceof Instruction && ((Instruction) prev).hasFallthrough());
	}

	private CodeUnit getPreviousCodeUnit(CodeUnit cu) {
		try {
			Address prevAddr = cu.getMinAddress().subtractNoWrap(1);
			return cu.getProgram().getListing().getCodeUnitContaining(prevAddr);
		}
		catch (AddressOverflowException e) {
			// we are just being lazy and not validating before doing the subtract--SOCK!
		}
		return null;
	}

	private boolean isTransitionCode(CodeUnit cu) {
		CodeUnit previous = getPreviousCodeUnit(cu);
		if (cu instanceof Instruction) {
			return !(previous instanceof Instruction);
		}
		return !(previous instanceof Data);
	}

	private boolean hasReferencesTo(CodeUnit cu) {
		return cu.getProgram().getReferenceManager().hasReferencesTo(cu.getMinAddress());
	}

	private void init(Options options) {
		if (initialized) {
			return;
		}
		initialized = true;

		StringBuilder sb = new StringBuilder();
		sb.append("\n");
		for (int i = 0; i < 19; i++) {
			sb.append("|");
		}

		HelpLocation help = new HelpLocation(HelpTopics.CODE_BROWSER, "Format_Code");
		options.getOptions(GROUP_TITLE).setOptionsHelpLocation(help);

		options.registerOption(ENABLE_WORD_WRAP_MSG, false, null,
			"Enables word wrapping in the pre-comments field.  If word " +
				"wrapping is on, user enter new lines are ignored and " +
				"the entire comment is displayed in paragraph form.  If word " +
				"wrapping is off, comments are displayed in line format " +
				"however the user entered them.  Lines that are too long " +
				"for the field, are truncated.");

		options.registerOption(SHOW_SUBROUTINE_PLATES_OPTION, true, help,
			"Toggle for whether a plate comment should be displayed for subroutines.");
		options.registerOption(SHOW_FUNCTION_PLATES_OPTION, true, help,
			"Toggle for whether a plate comment should be displayed for functions.");
//		options.registerOption(SHOW_CASE_PLATES_OPTION,false, help,
//			"Toggle for whether a plate comment should be displayed for a case statement.");
		options.registerOption(SHOW_TRANSITION_PLATES_OPTION, false, help,
			"Toggle for whether a plate comment should be displayed for a change " +
				"in the flow type between instructions, when data follows " +
				"an instruction, an instruction follows data, or dead code is detected.");
		options.registerOption(SHOW_EXT_ENTRY_PLATES_OPTION, false, help,
			"Toggle for whether a plate comment should be displayed " + "at an entry point.");
		options.registerOption(LINES_BEFORE_LABELS_OPTION, 1, help,
			"Number of lines to displayed before a label.");
		options.registerOption(LINES_BEFORE_FUNCTIONS_OPTION, 0, help,
			"Number of lines to displayed before the start of a function." +
				" This setting has precedence over Lines Before Plates.");
		options.registerOption(LINES_BEFORE_PLATES_OPTION, 0, help,
			"Number of lines to displayed before a plate comment." +
				" This setting has precedence over Lines Before Labels.");

		help = new HelpLocation(HelpTopics.CODE_BROWSER, "Function_Pointers");
		options.registerOption(ListingModel.DISPLAY_EXTERNAL_FUNCTION_POINTER_OPTION_NAME, true,
			help, "Shows/hides function header format for pointers to external functions");
		options.registerOption(ListingModel.DISPLAY_NONEXTERNAL_FUNCTION_POINTER_OPTION_NAME, false,
			help, "Shows/hides function header format for pointers to non-external functions");
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class PlateListingTextField extends ListingTextField {

		protected PlateListingTextField(ProxyObj<?> proxy, PlateFieldTextField field) {
			super(PlateFieldFactory.this, proxy, field);
		}

		PlateFieldTextField getPlateTextField() {
			return (PlateFieldTextField) field;
		}
	}

	private class PlateFieldTextField extends VerticalLayoutTextField {

		private boolean isCommentClipped;
		private String commentText;

		public PlateFieldTextField(List<FieldElement> textElements, PlateFieldFactory factory,
				ProxyObj<?> proxy, int startX, int width, String commentText,
				boolean isCommentClipped) {
			super(textElements, startX, width, Integer.MAX_VALUE,
				new FieldHighlightFactory(hlProvider, factory.getClass(), proxy.getObject()));
			this.commentText = commentText;
			this.isCommentClipped = isCommentClipped;
		}

		@Override
		public boolean isClipped() {
			return isCommentClipped;
		}

		@Override
		public String getTextWithLineSeparators() {
			return commentText;
		}

		int getLeadingFillerLineCount() {
			int count = 0;

			for (String line : getLines()) {
				count++;
				if (line.isEmpty()) {
					continue; // skip leading blank lines
				}

				if (line.startsWith("*")) {
					break;
				}
			}

			return count;
		}
	}

	private class FieldElementResult {
		private FieldElement element;
		private boolean isClipped;

		FieldElementResult(FieldElement element, boolean isClipped) {
			this.element = element;
			this.isClipped = isClipped;
		}

		boolean isClipped() {
			return isClipped;
		}

		FieldElement getFieldElement() {
			return element;
		}
	}
}
