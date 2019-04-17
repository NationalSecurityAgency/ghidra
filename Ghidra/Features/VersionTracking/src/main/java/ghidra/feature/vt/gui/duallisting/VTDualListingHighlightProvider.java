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
package ghidra.feature.vt.gui.duallisting;

import ghidra.app.plugin.core.codebrowser.ListingHighlightProvider;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.field.*;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.*;
import ghidra.feature.vt.api.stringable.*;
import ghidra.feature.vt.api.util.Stringable;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

import java.awt.Color;
import java.util.*;

import docking.widgets.fieldpanel.support.Highlight;

public class VTDualListingHighlightProvider implements HighlightProvider {

	private static Color APPLIED_MARKUP_COLOR = new Color(150, 220, 150); // green
	private static Color UNAPPLIED_MARKUP_COLOR = new Color(255, 170, 85); // orange
	private static Color IGNORED_MARKUP_COLOR = new Color(220, 220, 220); // gray
	private static Color REJECTED_MARKUP_COLOR = new Color(250, 200, 200); // pink
	private static Color FAILED_MARKUP_COLOR = new Color(255, 80, 80); // red
	private static Color NO_ADDRESS_MARKUP_COLOR = new Color(205, 185, 220); // purple
	private static Color SAME_MARKUP_COLOR = new Color(175, 225, 255); // light blue
	private static Color CONFLICT_MARKUP_COLOR = new Color(255, 225, 105); // gold

	private HashMap<Address, HashMap<VTMarkupType, VTMarkupItem>> map =
		new HashMap<Address, HashMap<VTMarkupType, VTMarkupItem>>();
	private final VTController controller;
	private ListingPanel listingPanel;
	private ListingHighlightProvider listingHighlighter;

	private VTMarkupItem currentMarkupItem;
	private boolean isSource;

	public VTDualListingHighlightProvider(VTController controller, boolean isSource) {
		this.controller = controller;
		this.isSource = isSource;
		updateMarkup();
	}

	public void setListingPanel(ListingPanel listingPanel) {
		if (this.listingPanel != null) {
			this.listingPanel.removeButtonPressedListener(listingHighlighter);
		}

		this.listingPanel = listingPanel;

		if (listingPanel != null) {
			this.listingHighlighter =
				new ListingHighlightProvider(controller.getTool(), listingPanel);
			listingPanel.removeButtonPressedListener(listingHighlighter);
			listingPanel.addButtonPressedListener(listingHighlighter);
		}
	}

	public void updateMarkup() {

		map.clear();

		VTSession session = controller.getSession();
		if (session == null) {
			return;
		}

		MatchInfo matchInfo = controller.getMatchInfo();
		if (matchInfo != null) {
			Collection<VTMarkupItem> markupItems = matchInfo.getAppliableMarkupItems(null);
			for (VTMarkupItem markupItem : markupItems) {
				// Put item in source map.
				updateMap(markupItem);
			}
		}
	}

	private void updateMap(VTMarkupItem markupItem) {
		VTMarkupType markupType = markupItem.getMarkupType();
		Address address;
		if (isSource) {
			address = markupItem.getSourceAddress();
		}
		else {
			address = markupItem.getDestinationAddress();
		}
		if (address == null || address == Address.NO_ADDRESS) {
			return;
		}

		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(address);
		if (typeMap == null) {
			typeMap = new HashMap<VTMarkupType, VTMarkupItem>();
			map.put(address, typeMap);
		}

		typeMap.put(markupType, markupItem);
	}

	@Override
	public Highlight[] getHighlights(String text, Object obj,
			Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {

		VTSession session = controller.getSession();
		if (session == null) {
			throw new AssertException("Oh No! Session is null!");
//	        return new Highlight[0]; // shouldn't happen
		}

		MatchInfo matchInfo = controller.getMatchInfo();
		if (matchInfo == null) {
			return new Highlight[0];
		}
		Highlight[] highlights = new Highlight[0];

		if (fieldFactoryClass == FunctionSignatureFieldFactory.class) {
			highlights = getFunctionSignatureHighlights(text, obj, cursorTextOffset);
		}

//		if ((fieldFactoryClass == FunctionSignatureFieldFactory.class) ||
//			(fieldFactoryClass == VariableTypeFieldLocation.class) ||
//			(fieldFactoryClass == VariableLocFieldLocation.class)) {
//			highlights = getFunctionSignatureHighlights(text, obj, cursorTextOffset);
//		}
		if ((fieldFactoryClass == FunctionRepeatableCommentFieldFactory.class) ||
			(fieldFactoryClass == EolCommentFieldFactory.class)) {
			highlights = getRepeatableCommentHighlights(text, obj, cursorTextOffset, highlights);
		}
		if ((fieldFactoryClass == VariableTypeFieldFactory.class) ||
			(fieldFactoryClass == VariableLocFieldFactory.class) ||
			(fieldFactoryClass == VariableNameFieldFactory.class) ||
			(fieldFactoryClass == VariableCommentFieldFactory.class)) {
			if (obj instanceof Parameter) {
				highlights = getFunctionSignatureParameterHighlights(text, obj, cursorTextOffset);
			}
//			else {
//				// TODO If we ever implement local variables, this needs a MarkupType for VariableLoc here.
//				highlights =
//					getVariableHighlights(text, obj, cursorTextOffset,
//						FunctionLocalVariableDataTypeMarkupType.INSTANCE);
//			}
		}
//		if ((fieldFactoryClass == VariableNameFieldFactory.class) ||
//			(fieldFactoryClass == VariableCommentFieldFactory.class)) {
//			if (obj instanceof Parameter) {
//				highlights = getParameterNamesHighlights(text, obj, cursorTextOffset);
//			}
//			else {
//				VTMarkupType localVarMarkupType =
//					(fieldFactoryClass == VariableNameFieldFactory.class) ? FunctionLocalVariableNameMarkupType.INSTANCE
//							: FunctionLocalVariableCommentMarkupType.INSTANCE;
//				highlights = getVariableHighlights(text, obj, cursorTextOffset, localVarMarkupType);
//			}
//		}
		if (fieldFactoryClass == LabelFieldFactory.class) {
			highlights = getMultipleLabelsHighlights(text, obj, cursorTextOffset, highlights);
		}
		if (fieldFactoryClass == EolCommentFieldFactory.class) {
			highlights =
				getEntireCommentHighlights(EolCommentMarkupType.INSTANCE, text, obj,
					cursorTextOffset, highlights);
		}
		if (fieldFactoryClass == PlateFieldFactory.class) {
			highlights =
				getEntireCommentHighlights(PlateCommentMarkupType.INSTANCE, text, obj,
					cursorTextOffset, highlights);
		}
		if (fieldFactoryClass == PreCommentFieldFactory.class) {
			highlights =
				getEntireCommentHighlights(PreCommentMarkupType.INSTANCE, text, obj,
					cursorTextOffset, highlights);
		}
		if (fieldFactoryClass == PostCommentFieldFactory.class) {
			highlights =
				getEntireCommentHighlights(PostCommentMarkupType.INSTANCE, text, obj,
					cursorTextOffset, highlights);
		}
		if (fieldFactoryClass == MnemonicFieldFactory.class) {
			highlights =
				getListingDataTypeHighlights(DataTypeMarkupType.INSTANCE, text, obj,
					cursorTextOffset, highlights);
		}

		List<Highlight> highlightList = new ArrayList<Highlight>();

		for (Highlight highlight : highlights) {
			highlightList.add(highlight);
		}

		highlightList.addAll(getListingHighlights(text, obj, fieldFactoryClass, cursorTextOffset));

		return highlightList.toArray(new Highlight[highlightList.size()]);
	}

	private Collection<? extends Highlight> getListingHighlights(String text, Object obj,
			Class<? extends FieldFactory> fieldFactoryClass, int cursorTextOffset) {
		if (listingHighlighter == null) {
			return Collections.emptyList();
		}

		return Arrays.asList(listingHighlighter.getHighlights(text, obj, fieldFactoryClass,
			cursorTextOffset));
	}

	private Color getMarkupBackgroundColor(int cursorTextOffset, VTMarkupItem vtMarkupItem,
			int startIndex, int endIndex) {
		Color highlightColor = null;
		Address sourceAddress = vtMarkupItem.getSourceAddress();
		Address destinationAddress = vtMarkupItem.getDestinationAddress();
		VTMarkupItemStatus status = vtMarkupItem.getStatus();
		if (status == VTMarkupItemStatus.DONT_CARE) {
			highlightColor = IGNORED_MARKUP_COLOR;
		}
		else if (status == VTMarkupItemStatus.DONT_KNOW) {
			highlightColor = IGNORED_MARKUP_COLOR;
		}
		else if (status == VTMarkupItemStatus.REJECTED) {
			highlightColor = REJECTED_MARKUP_COLOR;
		}
		else if (status == VTMarkupItemStatus.CONFLICT) {
			highlightColor = CONFLICT_MARKUP_COLOR;
		}
		else if (destinationAddress == null || destinationAddress == Address.NO_ADDRESS) {
			highlightColor = NO_ADDRESS_MARKUP_COLOR;
		}
		else if (status == VTMarkupItemStatus.UNAPPLIED) {
			highlightColor = UNAPPLIED_MARKUP_COLOR;
		}
		else if (status.isUnappliable()) {
			highlightColor = APPLIED_MARKUP_COLOR;
		}
		else if (status == VTMarkupItemStatus.FAILED_APPLY) {
			highlightColor = FAILED_MARKUP_COLOR;
		}
		else if (status == VTMarkupItemStatus.SAME) {
			highlightColor = SAME_MARKUP_COLOR;
		}
		else {
			return null;
		}
		if (currentMarkupItem != null) {
			VTMarkupType currentMarkupType = currentMarkupItem.getMarkupType();
			VTMarkupType markupType = vtMarkupItem.getMarkupType();
			Address currentSourceAddress = currentMarkupItem.getSourceAddress();
			boolean inCurrentMarkup =
				(currentMarkupType == markupType) && currentSourceAddress.equals(sourceAddress);
			if (inCurrentMarkup) {
				// Set the highlight color to be a bit darker than normal.  Color.darker() returns
				// a color that is too dark, so use this custom function instead.
				highlightColor = shade(highlightColor, 0.85);
			}
		}
		return highlightColor;
	}
	
	/**
	 * Creates a darker shade of the color passed-in, based on the given amount.
	 * 
	 * algorithm: 1) grab individual rgb elements
	 *            2) multiply each by a factor.
	 *            
	 *            ie: int newRed = (int)(oldRed * 0.85);
	 * 
	 * @param color the color to shade
	 * @param amount number between 0..1 (the smaller the number, the darker the shade)
	 * @return
	 */
	private static Color shade(Color color, double amount) {
		if (color != null) {
		
			int r = color.getRed();
			int g = color.getGreen();
			int b = color.getBlue();
			
			double newR = (r * amount);
			double newG = (g * amount);
			double newB = (b * amount);
			
			return new Color((int)newR, (int)newG, (int)newB);
		}
		
		return null;
	}

	@SuppressWarnings("unused")
	private Highlight[] getSpecificCommentHighlights(VTMarkupType commentType, String text,
			Object obj, int cursorTextOffset, Highlight[] highlights) {
		CodeUnit cu = (CodeUnit) obj;
		Address minAddress = cu.getMinAddress();
		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(minAddress);
		if (typeMap != null) {
			VTMarkupItem markupItem = typeMap.get(commentType);
			if (markupItem != null) {
				VTMarkupItemStatus status = markupItem.getStatus();
				StringStringable value =
					(StringStringable) ((isSource || markupItem.canUnapply()) ? markupItem.getSourceValue()
							: markupItem.getOriginalDestinationValue());
				String comment = value.getString();
				if (comment != null) {
					int startIndex = text.indexOf(comment);
					if (startIndex >= 0) {
						int endIndex = startIndex + comment.length() - 1;
						Color highlightColor =
							getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex,
								endIndex);
						Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
						highlights = new Highlight[] { highlight };
					}
				}
			}
		}
		return highlights;
	}

//	private Highlight[] getBothCommentHighlights(VTMarkupType commentType, String text, Object obj,
//			int cursorTextOffset, Highlight[] highlights) {
//
//		CodeUnit cu = (CodeUnit) obj;
//		Address minAddress = cu.getMinAddress();
//		ArrayList<Highlight> highlightList = new ArrayList<Highlight>();
//		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(minAddress);
//		if (typeMap != null) {
//			VTMarkupItem markupItem = typeMap.get(commentType);
//			if (markupItem != null) {
//				getBothStringHighlights(text, cursorTextOffset, highlightList, markupItem);
//			}
//		}
//		return highlightList.toArray(new Highlight[highlightList.size()]);
//	}

	private void getBothStringHighlights(String text, int cursorTextOffset,
			ArrayList<Highlight> highlightList, VTMarkupItem markupItem) {
		StringStringable sourceValue = (StringStringable) markupItem.getSourceValue();
		StringStringable destinationValue =
			(StringStringable) markupItem.getCurrentDestinationValue();

		String sourceComment = (sourceValue != null) ? sourceValue.getString() : null;
		String destinationComment =
			(destinationValue != null) ? destinationValue.getString() : null;

		if (sourceComment != null && sourceComment.length() > 0) {
			Highlight sourceHighlight =
				getHighlight(text, cursorTextOffset, markupItem, sourceComment);
			if (sourceHighlight != null) {
				highlightList.add(sourceHighlight);
			}
		}
		if (destinationComment != null && destinationComment.length() > 0) {
			Highlight destinationHighlight =
				getHighlight(text, cursorTextOffset, markupItem, destinationComment);
			if (destinationHighlight != null) {
				highlightList.add(destinationHighlight);
			}
		}
	}

	private Highlight getHighlight(String text, int cursorTextOffset, VTMarkupItem markupItem,
			String highlightString) {
		int startIndex = text.indexOf(highlightString);
		if (startIndex >= 0) {
			int endIndex = startIndex + highlightString.length() - 1;
			Color highlightColor =
				getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex, endIndex);
			return new Highlight(startIndex, endIndex, highlightColor);
		}
		return null;
	}

	private Highlight[] getEntireCommentHighlights(VTMarkupType commentType, String text,
			Object obj, int cursorTextOffset, Highlight[] highlights) {
		CodeUnit cu = (CodeUnit) obj;
		Address minAddress = cu.getMinAddress();
		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(minAddress);
		if (typeMap != null) {
			VTMarkupItem markupItem = typeMap.get(commentType);
			if (markupItem != null) {
				int startIndex = 0;
				int endIndex = text.length() - 1;
				Color highlightColor =
					getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex, endIndex);
				Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
				highlights = new Highlight[] { highlight };
			}
		}
		return highlights;
	}

	private Highlight[] getRepeatableCommentHighlights(String text, Object obj,
			int cursorTextOffset, Highlight[] highlights) {
		Address address = null;
		if (obj instanceof Function) {
			Function function = (Function) obj;
			address = function.getEntryPoint();
		}
		else if (obj instanceof CodeUnit) {
			CodeUnit codeUnit = (CodeUnit) obj;
			address = codeUnit.getMinAddress();
		}
		ArrayList<Highlight> highlightList = new ArrayList<Highlight>();
		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(address);
		if (typeMap != null) {
			VTMarkupItem markupItem = typeMap.get(RepeatableCommentMarkupType.INSTANCE);
			if (markupItem != null) {
				getBothStringHighlights(text, cursorTextOffset, highlightList, markupItem);
			}
		}
		return highlightList.toArray(new Highlight[highlightList.size()]);
	}

	private Highlight[] getFunctionSignatureHighlights(String text, Object obj, int cursorTextOffset) {
		Function function = null;
		if (obj instanceof Function) {
			function = (Function) obj;
		}
		else if (obj instanceof Variable) {
			Variable variable = (Variable) obj;
			function = variable.getFunction();
		}
		else {
			Msg.error(this, "Can't get highlights for a " + obj.getClass().getName());
			return new Highlight[0];
		}
		Address address = function.getEntryPoint();
		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(address);
		if (typeMap != null) {
			ArrayList<Highlight> highlightList = new ArrayList<Highlight>();

//			// Check if the text is in the Return Type
//			addFunctionHighlight(FunctionReturnTypeMarkupType.INSTANCE, text, cursorTextOffset,
//				typeMap, highlightList);

			// Check if the text is in the Function Name
			addFunctionNameHighlight(text, cursorTextOffset, typeMap, highlightList);

//			// Check if the text is in the Parameter Signature
//			addParameterSignatureHighlight(text, cursorTextOffset, typeMap, highlightList);

//			// Check if the text is in the Function Inline flag.
//			addFunctionInlineHighlight(text, cursorTextOffset, typeMap, highlightList);

//			// Check if the text is in the Function No Return flag.
//			addFunctionNoReturnHighlight(text, cursorTextOffset, typeMap, highlightList);

			// Check if the text is in the Function Signature (return type, calling convention, parameters).
			addFunctionSignatureHighlight(text, cursorTextOffset, typeMap, highlightList);

//			// Check if the text is in the Parameter Names.
//			addParameterNamesHighlight(text, cursorTextOffset, typeMap, highlightList);

			return highlightList.toArray(new Highlight[highlightList.size()]);
		}
		return new Highlight[0];
	}

	private Highlight[] getFunctionSignatureParameterHighlights(String text, Object obj,
			int cursorTextOffset) {
		if (!(obj instanceof Parameter)) {
			Msg.error(this, "Can't get highlights for a " + obj.getClass().getName());
			return new Highlight[0];
		}
		Parameter parameter = (Parameter) obj;
		Function function = parameter.getFunction();
		Address address = function.getEntryPoint();
		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(address);
		if (typeMap != null) {
			ArrayList<Highlight> highlightList = new ArrayList<Highlight>();

			VTMarkupItem markupItem = typeMap.get(FunctionSignatureMarkupType.INSTANCE);
			if (markupItem == null) {
				return new Highlight[0];
			}
			Color highlightColor =
				getMarkupBackgroundColor(cursorTextOffset, markupItem, 0, text.length() - 1);
			Highlight highlight = new Highlight(0, text.length() - 1, highlightColor);
			highlightList.add(highlight);

			return highlightList.toArray(new Highlight[highlightList.size()]);
		}
		return new Highlight[0];
	}

//	private Highlight[] getParameterNamesHighlights(String text, Object obj, int cursorTextOffset) {
//		if (!(obj instanceof Parameter)) {
//			Msg.error(this, "Can't get highlights for a " + obj.getClass().getName());
//			return new Highlight[0];
//		}
//		Parameter parameter = (Parameter) obj;
//		if (parameter.getOrdinal() == -1) {
//			return new Highlight[0];
//		}
//		Function function = parameter.getFunction();
//		Address address = function.getEntryPoint();
//		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(address);
//		if (typeMap != null) {
//			ArrayList<Highlight> highlightList = new ArrayList<Highlight>();
//
//			VTMarkupItem markupItem = typeMap.get(ParameterNamesMarkupType.INSTANCE);
//			if (markupItem == null) {
//				return new Highlight[0]; // Don't have a parameter names markup here.
//			}
//			Color highlightColor =
//				getMarkupBackgroundColor(cursorTextOffset, markupItem, 0, text.length() - 1);
//			Highlight highlight = new Highlight(0, text.length() - 1, highlightColor);
//			highlightList.add(highlight);
//
//			return highlightList.toArray(new Highlight[highlightList.size()]);
//		}
//		return new Highlight[0];
//	}

	@SuppressWarnings("unused")
	private void addFunctionHighlight(VTMarkupType markupType, String text, int cursorTextOffset,
			HashMap<VTMarkupType, VTMarkupItem> typeMap, ArrayList<Highlight> highlightList) {
		VTMarkupItem markupItem = typeMap.get(markupType);
		if (markupItem != null) {
			Stringable value =
				(isSource || markupItem.canUnapply()) ? markupItem.getSourceValue()
						: markupItem.getOriginalDestinationValue();
			if (value != null) {
				String displayString = value.getDisplayString();
				int startIndex = text.indexOf(displayString);
				if (startIndex >= 0) {
					int endIndex = startIndex + displayString.length() - 1;
					Color highlightColor =
						getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex, endIndex);
					Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
					highlightList.add(highlight);
				}
			}
		}
	}

	private void addFunctionNameHighlight(String text, int cursorTextOffset,
			HashMap<VTMarkupType, VTMarkupItem> typeMap, ArrayList<Highlight> highlightList) {
		VTMarkupItem markupItem = typeMap.get(FunctionNameMarkupType.INSTANCE);
		if (markupItem != null) {
			FunctionNameStringable value =
				(isSource || markupItem.canUnapply()) ? (FunctionNameStringable) markupItem.getSourceValue()
						: (FunctionNameStringable) markupItem.getOriginalDestinationValue();
			if (value != null) {
				int parameterStart = text.indexOf("(");
				if (parameterStart < 0) {
					parameterStart = text.length();
				}
				String name = value.getSymbolName();
				int startIndex = text.lastIndexOf(name, parameterStart - 1);
				if (startIndex >= 0) {
					int endIndex = startIndex + name.length() - 1;
					Color highlightColor =
						getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex, endIndex);
					Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
					highlightList.add(highlight);
				}
			}
		}
	}

//	@SuppressWarnings("unused")
//	private void addParameterSignatureHighlight(String text, int cursorTextOffset,
//			HashMap<VTMarkupType, VTMarkupItem> typeMap, ArrayList<Highlight> highlightList) {
//		VTMarkupItem markupItem = typeMap.get(ParametersSignatureMarkupType.INSTANCE);
//		if (markupItem != null) {
//			int startIndex = text.indexOf("("); // Include left parenthesis
//			int endIndex = text.indexOf(")"); // Include right parenthesis
//
//			// Is there some way to determine a field can't display all its info and has a "..."?
//			if (startIndex >= 0 && endIndex == -1) { // Didn't find right paren so get end of text.
//				endIndex = text.length();
//			}
//
//			if (startIndex >= 0 && endIndex >= 0) {
//				Color highlightColor =
//					getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex, endIndex);
//				Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
//				highlightList.add(highlight);
//			}
//		}
//	}

	private void addFunctionSignatureHighlight(String text, int cursorTextOffset,
			HashMap<VTMarkupType, VTMarkupItem> typeMap, ArrayList<Highlight> highlightList) {
		VTMarkupItem markupItem = typeMap.get(FunctionSignatureMarkupType.INSTANCE);
		if (markupItem != null) {
			int textLength = text.length();

			int leftParenIndex = text.indexOf("(");
			int rightParenIndex = text.indexOf(")");

			int startReturnIndex = 0;
			int endCallingConventionIndex = textLength - 1;
			if (leftParenIndex >= 0) {
				int beforeNameIndex = getLastIndexOf(text, leftParenIndex - 1, ' ');
				if (beforeNameIndex >= 0) {
					endCallingConventionIndex = beforeNameIndex - 1;
				}
			}
//			if (text.startsWith("inline ", startReturnIndex)) {
//				Color highlightColor = getMarkupBackgroundColor(cursorTextOffset, markupItem, 0, 5);
//				Highlight highlight = new Highlight(0, 5, highlightColor);
//				highlightList.add(highlight);
//
//				startReturnIndex += 7;
//			}
//			if (text.startsWith("noreturn ", startReturnIndex)) {
//				startReturnIndex += 9;
//			}

			if (startReturnIndex >= 0 && endCallingConventionIndex >= 0) {
				Color highlightColor =
					getMarkupBackgroundColor(cursorTextOffset, markupItem, startReturnIndex,
						endCallingConventionIndex);
				Highlight highlight =
					new Highlight(startReturnIndex, endCallingConventionIndex, highlightColor);
				highlightList.add(highlight);
			}

			if (leftParenIndex == -1) {
				return; // No left parenthesis or parameters showing.
			}
			int startParamsIndex = leftParenIndex + 1;
			if (startParamsIndex >= textLength) {
				return; // No parameters showing.
			}
			int endParamsIndex = textLength;
			if (rightParenIndex >= 0) {
				endParamsIndex = rightParenIndex - 1;
			}
			if (endParamsIndex <= startParamsIndex) {
				return; // No parameters showing.
			}

			// Use the following to get just the data types.
			// Otherwise use the highlight below the while loop to get both data types and names 
			// in the function signature.
//			int nextParamIndex = startParamsIndex;
//			while (nextParamIndex >= 0) {
//				int dtStartIndex = nextParamIndex;
//				int dtEndIndex = endParamsIndex - 1;
//				int commaIndex = text.indexOf(',', nextParamIndex);
//				int preNameIndex = -1;
//				if (commaIndex == -1) {
//					// Check for VarArgs.
//					if (text.startsWith("...)", dtStartIndex)) {
//						dtEndIndex = dtStartIndex + 2; // gets all 3 dots for the varArgs.
//					}
//					else {
//						// process last visible parameter.
//						if (rightParenIndex != -1) {
//							preNameIndex = getLastIndexOf(text, endParamsIndex, ' ');
//						}
//						else {
//							preNameIndex = getLastIndexOf(text, commaIndex - 1, ' ');
//						}
//					}
//					nextParamIndex = -1;
//				}
//				else {
//					// process non-last visible parameter.
//					preNameIndex = getLastIndexOf(text, commaIndex - 1, ' ');
//					nextParamIndex = commaIndex + 1;
//					if (text.charAt(nextParamIndex) == ' ') {
//						nextParamIndex++;
//					}
//				}
//				if (preNameIndex >= 0) {
//					dtEndIndex = preNameIndex - 1;
//				}
//				Color highlightColor =
//					getMarkupBackgroundColor(cursorTextOffset, markupItem, dtStartIndex, dtEndIndex);
//				Highlight highlight = new Highlight(dtStartIndex, dtEndIndex, highlightColor);
//				highlightList.add(highlight);
//			}
			// Use the following if data types and names are all grouped into the function signature.
			// Otherwise use the while loop above to get just the data types.
			Color highlightColor =
				getMarkupBackgroundColor(cursorTextOffset, markupItem, startParamsIndex,
					endParamsIndex);
			Highlight highlight = new Highlight(startParamsIndex, endParamsIndex, highlightColor);
			highlightList.add(highlight);
		}
	}

//
//	@SuppressWarnings("unused")
//	private void addFunctionInlineHighlight(String text, int cursorTextOffset,
//			HashMap<VTMarkupType, VTMarkupItem> typeMap, ArrayList<Highlight> highlightList) {
//		VTMarkupItem markupItem = typeMap.get(FunctionInlineMarkupType.INSTANCE);
//		if (markupItem != null) {
//			int textLength = text.length();
//
//			int startIndex = 0;
//			if (text.startsWith("inline ", startIndex)) {
//				int endIndex = startIndex + 5;
//				if (endIndex > textLength) {
//					endIndex = textLength;
//				}
//				Color highlightColor =
//					getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex, endIndex);
//				Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
//				highlightList.add(highlight);
//			}
//		}
//	}
//
//	private void addFunctionNoReturnHighlight(String text, int cursorTextOffset,
//			HashMap<VTMarkupType, VTMarkupItem> typeMap, ArrayList<Highlight> highlightList) {
//		VTMarkupItem markupItem = typeMap.get(FunctionNoReturnMarkupType.INSTANCE);
//		if (markupItem != null) {
//			int textLength = text.length();
//
//			int startIndex = 0;
//			if (text.startsWith("inline ", startIndex)) {
//				startIndex += 7;
//			}
//			if (text.startsWith("noreturn ", startIndex)) {
//				int endIndex = startIndex + 7;
//				if (endIndex > textLength) {
//					endIndex = textLength;
//				}
//				Color highlightColor =
//					getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex, endIndex);
//				Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
//				highlightList.add(highlight);
//			}
//		}
//	}
//
//	private void addParameterNamesHighlight(String text, int cursorTextOffset,
//			HashMap<VTMarkupType, VTMarkupItem> typeMap, ArrayList<Highlight> highlightList) {
//		VTMarkupItem markupItem = typeMap.get(ParameterNamesMarkupType.INSTANCE);
//		if (markupItem != null) {
//			int textLength = text.length();
//			boolean hasVarArgs = text.endsWith("...)");
//			int leftParenIndex = text.indexOf("("); // Include left parenthesis
//			int rightParenIndex = text.indexOf(")"); // Include right parenthesis
//			if (leftParenIndex == -1) {
//				return; // No left parenthesis or parameters showing.
//			}
//			int startParamsIndex = leftParenIndex + 1;
//			if (startParamsIndex >= textLength) {
//				return; // No parameters showing.
//			}
//			int endParamsIndex = textLength;
//			if (rightParenIndex >= 0) {
//				endParamsIndex = rightParenIndex - 1;
//			}
//			if (endParamsIndex <= startParamsIndex) {
//				return; // No parameters showing.
//			}
//
//			int nextParamIndex = startParamsIndex;
//			while (nextParamIndex >= 0) {
//				int commaIndex = text.indexOf(',', nextParamIndex);
//				int preNameIndex = -1;
//				if (commaIndex == -1) {
//					// Check for VarArgs.
//					if (!hasVarArgs) {
//						// process last visible parameter.
//						if (rightParenIndex != -1) {
//							preNameIndex = getLastIndexOf(text, endParamsIndex, ' ');
//						}
//						else {
//							preNameIndex = getLastIndexOf(text, commaIndex - 1, ' ');
//						}
//					}
//					nextParamIndex = -1;
//				}
//				else {
//					// process non-last visible parameter.
//					preNameIndex = getLastIndexOf(text, commaIndex - 1, ' ');
//					nextParamIndex = commaIndex + 1;
//				}
//				if (preNameIndex >= 0) {
//					int startNameIndex = preNameIndex + 1;
//					if (startNameIndex >= textLength) {
//						return;
//					}
//					int endNameIndex = textLength - 1;
//					if (commaIndex >= 0) {
//						endNameIndex = commaIndex - 1;
//					}
//					else if (rightParenIndex >= 0) {
//						endNameIndex = rightParenIndex - 1;
//					}
//					Color highlightColor =
//						getMarkupBackgroundColor(cursorTextOffset, markupItem, startNameIndex,
//							endNameIndex);
//					Highlight highlight =
//						new Highlight(startNameIndex, endNameIndex, highlightColor);
//					highlightList.add(highlight);
//				}
//			}
//		}
//	}

	private int getLastIndexOf(String text, int backwardsIndex, char c) {
		for (int i = backwardsIndex; i >= 0; i--) {
			if (c == text.charAt(i)) {
				return i;
			}
		}
		return -1;
	}

	private Highlight[] getVariableHighlights(String text, Object obj, int cursorTextOffset,
			VTMarkupType markupType) {

		Variable variable = (Variable) obj;
		Address storageAddress = variable.getMinAddress();
		if (storageAddress == null) {
			return new Highlight[0];
		}
		ArrayList<Highlight> highlightList = new ArrayList<Highlight>();
		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(storageAddress);
		if (typeMap != null) {
			VTMarkupItem markupItem = typeMap.get(markupType);
			if ((markupItem != null) && isCorrectFunction(variable, markupItem)) {
				if (variable instanceof Parameter) {
					addParametersHighlight(text, cursorTextOffset, markupItem, highlightList);
				}
				else {
					addLocalVariablesHighlight(text, cursorTextOffset, markupItem, highlightList);
				}
			}
		}
		return highlightList.toArray(new Highlight[highlightList.size()]);
	}

	private boolean isCorrectFunction(Variable variable, VTMarkupItem markupItem) {
		Function function = variable.getFunction();
		Address variableFunctionAddress = function.getEntryPoint();
		Program program = function.getProgram();
		VTAssociation association = markupItem.getAssociation();
		VTSession session = association.getSession();
		Program sourceProgram = session.getSourceProgram();
		Program destinationProgram = session.getDestinationProgram();
		if (program == sourceProgram) {
			Address markupFunctionAddress = association.getSourceAddress();
			if (!variableFunctionAddress.equals(markupFunctionAddress)) {
				return false;
			}
		}
		else if (program == destinationProgram) {
			Address markupFunctionAddress = association.getDestinationAddress();
			if (!variableFunctionAddress.equals(markupFunctionAddress)) {
				return false;
			}
		}
		else {
			return false;
		}
		return true;
	}

	private void addParametersHighlight(String text, int cursorTextOffset,
			VTMarkupItem parameterMarkupItem, ArrayList<Highlight> highlightList) {

		if (parameterMarkupItem != null) {
			int startIndex = 0;
			int endIndex = text.length() - 1;
			if (endIndex >= 0) {
				Color highlightColor =
					getMarkupBackgroundColor(cursorTextOffset, parameterMarkupItem, startIndex,
						endIndex);
				Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
				highlightList.add(highlight);
			}
		}
	}

	private void addLocalVariablesHighlight(String text, int cursorTextOffset,
			VTMarkupItem localVariableMarkupItem, ArrayList<Highlight> highlightList) {

		if (localVariableMarkupItem != null) {
			int startIndex = 0;
			int endIndex = text.length() - 1;
			if (endIndex >= 0) {
				Color highlightColor =
					getMarkupBackgroundColor(cursorTextOffset, localVariableMarkupItem, startIndex,
						endIndex);
				Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
				highlightList.add(highlight);
			}
		}
	}

	private Highlight[] getMultipleLabelsHighlights(String text, Object obj, int cursorTextOffset,
			Highlight[] highlights) {
		CodeUnit cu = (CodeUnit) obj;
		Address minAddress = cu.getMinAddress();
		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(minAddress);
		if (typeMap != null) {
			VTMarkupItem markupItem = typeMap.get(LabelMarkupType.INSTANCE);
			if (markupItem != null) {
				ArrayList<Highlight> highlightList = new ArrayList<Highlight>();
				MultipleSymbolStringable value =
					(MultipleSymbolStringable) ((isSource || markupItem.canUnapply()) ? markupItem.getSourceValue()
							: markupItem.getOriginalDestinationValue());
				if (value != null) {
					// Highlight the entire labels field.
					int startIndex = 0;
					int endIndex = text.length() - 1;
					Color highlightColor =
						getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex, endIndex);
					Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
					highlightList.add(highlight);
					return highlightList.toArray(new Highlight[highlightList.size()]);
				}
			}
		}
		return new Highlight[0];
	}

	private Highlight[] getListingDataTypeHighlights(VTMarkupType markupType, String text,
			Object obj, int cursorTextOffset, Highlight[] highlights) {

		CodeUnit cu = (CodeUnit) obj;
		Address minAddress = cu.getMinAddress();
		HashMap<VTMarkupType, VTMarkupItem> typeMap = map.get(minAddress);
		if (typeMap != null) {
			VTMarkupItem markupItem = typeMap.get(DataTypeMarkupType.INSTANCE);
			if (markupItem != null) {
				ArrayList<Highlight> highlightList = new ArrayList<Highlight>();
				DataTypeStringable value =
					(DataTypeStringable) ((isSource || markupItem.canUnapply()) ? markupItem.getSourceValue()
							: markupItem.getOriginalDestinationValue());
				if (value != null) {
					Program sourceProgram =
						markupType.getSourceProgram(markupItem.getAssociation());
					DataTypeManager sourceDTM = sourceProgram.getDataTypeManager();
					Program destinationProgram =
						markupType.getDestinationProgram(markupItem.getAssociation());
					DataTypeManager destinationDTM = destinationProgram.getDataTypeManager();
					DataTypeManager dataTypeManager =
						(isSource || markupItem.canUnapply()) ? sourceDTM : destinationDTM;

					DataType dataType = value.getDataType(dataTypeManager);
					String mnemonic = dataType.getMnemonic(dataType.getDefaultSettings());

					// Just select all the mnemonic text for now.
					if (text != null) {
						int startIndex = text.indexOf(mnemonic);
						int endIndex = startIndex + mnemonic.length() - 1;
						Color highlightColor =
							getMarkupBackgroundColor(cursorTextOffset, markupItem, startIndex,
								endIndex);
						Highlight highlight = new Highlight(startIndex, endIndex, highlightColor);
						highlightList.add(highlight);
					}
				}
				return highlightList.toArray(new Highlight[highlightList.size()]);
			}
		}
		return new Highlight[0];
	}

	public void setMarkupItem(VTMarkupItem markupItem) {
		if (markupItem == currentMarkupItem) {
			return;
		}
		currentMarkupItem = markupItem;
		updateMarkup();
	}

	public VTMarkupItem getMarkupItem() {
		return currentMarkupItem;
	}

	public boolean isSource() {
		return isSource;
	}
}
