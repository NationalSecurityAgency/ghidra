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

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldUtils;
import ghidra.app.util.HighlightProvider;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOverride;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.*;

/**
  *  Generates post comment Fields.
  */
public class PostCommentFieldFactory extends FieldFactory {

	private static String[] EMPTY_STRING_ARRAY = new String[0];

	public static final String FIELD_NAME = "Post-Comment";

	private final static String GROUP_TITLE = "Format Code";
	private final static String FIELD_GROUP_TITLE = "Post-comments Field";
	public final static String ENABLE_WORD_WRAP_MSG =
		FIELD_GROUP_TITLE + Options.DELIMITER + "Enable Word Wrapping";
	public final static String ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG =
		FIELD_GROUP_TITLE + Options.DELIMITER + "Always Show the Automatic Comment";

	final static String FLAG_FUNCTION_EXIT_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Flag Function Exits";
	final static String FLAG_TERMINATOR_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Flag Jumps and Returns";
	final static String LINES_AFTER_BLOCKS_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Lines After Basic Blocks";

	static String DEFAULT_FLAG_COMMENT;

	final static String FUN_EXIT_FLAG_LEADER = "********** ";
	final static String FUN_EXIT_FLAG_TAIL = " Exit ********** ";

	private boolean flagJMPsRETs;
	private boolean flagFunctionExits;
	private int nLinesAfterBlocks;
	private boolean isWordWrap;
	private boolean alwaysShowAutomatic;
	private Color automaticCommentColor;
	private int automaticCommentStyle;

	/**
	 * Constructor
	 */
	public PostCommentFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private PostCommentFieldFactory(FieldFormatModel model, HighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

		fieldOptions.registerOption(FLAG_FUNCTION_EXIT_OPTION, false, null,
			"Toggles the display of a post-comment for a function exit");
		fieldOptions.registerOption(FLAG_TERMINATOR_OPTION, false, null,
			"Toggles the display of a jump/return post-comments");
		fieldOptions.registerOption(LINES_AFTER_BLOCKS_OPTION, 0, null,
			"The number of lines to display after basic blocks");

		flagFunctionExits = fieldOptions.getBoolean(FLAG_FUNCTION_EXIT_OPTION, false);
		flagJMPsRETs = fieldOptions.getBoolean(FLAG_TERMINATOR_OPTION, false);
		nLinesAfterBlocks = fieldOptions.getInt(LINES_AFTER_BLOCKS_OPTION, 0);

		automaticCommentColor =
			displayOptions.getColor(OptionsGui.COMMENT_AUTO.getColorOptionName(),
				OptionsGui.COMMENT_AUTO.getDefaultColor());
		automaticCommentStyle =
			displayOptions.getInt(OptionsGui.COMMENT_AUTO.getStyleOptionName(), -1);

		init(fieldOptions);
	}

	/**
	 *
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

		// If this code unit is the outside of a data
		// container, then do not display any comments.
		// If this was allowed, then the comment would appear
		// on the outside data container and on the 1st
		// internal member
		//
		if (cu instanceof Data) {
			Data data = (Data) cu;
			if (data.getNumComponents() > 0) {
				return null;
			}
		}

		String[] autoComment = getAutoPostComment(cu);

		String[] comments = cu.getCommentAsArray(CodeUnit.POST_COMMENT);
		if (comments != null && comments.length > 0 && (cu instanceof Data)) {
			return getTextField(comments, autoComment, proxy, x, false);
		}
		if (cu instanceof Instruction) {
			Instruction instr = (Instruction) cu;
			if (instr.getDelaySlotDepth() > 0) {
				if (comments != null && comments.length > 0) {
					return getTextField(comments, null, proxy, x, false);
				}
				return null;
			}
			// check field options
			return getTextFieldForOptions(instr, comments, autoComment, proxy, x);
		}
		return null;
	}

	private String[] getAutoPostComment(CodeUnit cu) {

		if (!(cu instanceof Instruction)) {
			return null;
		}
		Instruction instr = (Instruction) cu;
		LinkedList<String> comments = new LinkedList<>();

		if (instr.isInDelaySlot()) {
			// ensure that auto-comment come from parent and are only placed after last
			// delay slot.  Switch out inst with the parent instruction
			int delaySlotPosition = 0;
			while (instr.isInDelaySlot()) {
				++delaySlotPosition;
				instr = instr.getPrevious();
			}
			if (instr.getDelaySlotDepth() != delaySlotPosition) {
				return null; // not the last delay slot
			}
		}

		if (instr.isFallThroughOverridden()) {
			Address fallThrough = instr.getFallThrough();
			String fallthroughComment = "-- Fallthrough Override: " +
				(fallThrough != null ? fallThrough.toString() : "NO-FALLTHROUGH");
			comments.addFirst(fallthroughComment);
		}
		FlowOverride flowOverride = instr.getFlowOverride();
		if (flowOverride != FlowOverride.NONE) {
			String flowOverrideComment =
				"-- Flow Override: " + flowOverride + " (" + instr.getFlowType().getName() + ")";
			comments.addFirst(flowOverrideComment);
		}

		InstructionPcodeOverride pCodeOverride = new InstructionPcodeOverride(instr);

		if (pCodeOverride.hasPotentialOverride()) {
			PcodeOp[] pcodeOps = instr.getPcode();
			OverrideCommentData overrideData = null;
			if (pCodeOverride.getPrimaryCallReference() == null) {
				overrideData = getOverrideCommentData(instr, RefType.CALL_OVERRIDE_UNCONDITIONAL,
					pcodeOps, pCodeOverride);
				if (overrideData != null) {
					String callOverrideComment =
						"-- Call Destination Override: " + getOverridingCommentDestString(
							overrideData.getOverridingRef(), instr.getProgram());
					comments.addFirst(callOverrideComment);
				}
			}
			overrideData = getOverrideCommentData(instr, RefType.JUMP_OVERRIDE_UNCONDITIONAL,
				pcodeOps, pCodeOverride);
			if (overrideData != null) {
				String jumpOverrideComment =
					"-- Jump Destination Override: " + getOverridingCommentDestString(
						overrideData.getOverridingRef(), instr.getProgram());
				comments.addFirst(jumpOverrideComment);
			}
			overrideData = getOverrideCommentData(instr, RefType.CALLOTHER_OVERRIDE_CALL, pcodeOps,
				pCodeOverride);
			if (overrideData != null) {
				String callOtherCallOverrideComment =
					"-- CALLOTHER(" + overrideData.getOverriddenCallOther() + ") Call Override: " +
						getOverridingCommentDestString(overrideData.getOverridingRef(),
							instr.getProgram());
				if (overrideData.hasMultipleCallOthers()) {
					comments.addFirst("-- WARNING: additional CALLOTHER ops present");
				}
				String outputWarningString = overrideData.getOutputWarningString();
				if (outputWarningString != null) {
					comments.addFirst(outputWarningString);
				}
				else {
					comments.addFirst(callOtherCallOverrideComment);
				}
			}
			else {
				overrideData = getOverrideCommentData(instr, RefType.CALLOTHER_OVERRIDE_JUMP,
					pcodeOps, pCodeOverride);
				if (overrideData != null) {
					String callOtherJumpOverrideComment =
						"-- CALLOTHER(" + overrideData.getOverriddenCallOther() +
							") Jump Override: " + getOverridingCommentDestString(
								overrideData.getOverridingRef(), instr.getProgram());
					if (overrideData.hasMultipleCallOthers()) {
						comments.addFirst("-- WARNING: additional CALLOTHER ops present");
					}
					String outputWarningString = overrideData.getOutputWarningString();
					if (outputWarningString != null) {
						comments.addFirst(outputWarningString);
					}
					else {
						comments.addFirst(callOtherJumpOverrideComment);
					}
				}
			}
		}
		if (comments.size() > 0) {
			return comments.toArray(new String[0]);
		}
		return null;
	}

	private String getOverridingCommentDestString(Address address, Program program) {
		StringBuilder sb = new StringBuilder();
		String symbol = program.getSymbolTable().getPrimarySymbol(address).getName(true);
		if (!StringUtils.isEmpty(symbol)) {
			sb.append(symbol);
			sb.append(" ");
		}
		sb.append("(");
		sb.append(address.toString());
		sb.append(")");
		return sb.toString();
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getProgramLocation(int, int, ghidra.app.util.viewer.field.ListingField)
	 */
	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}

		CodeUnit cu = (CodeUnit) obj;
		String[] comment = cu.getCommentAsArray(CodeUnit.POST_COMMENT);

		int[] cpath = null;
		if (cu instanceof Data) {
			cpath = ((Data) cu).getComponentPath();
		}

		return new PostCommentFieldLocation(cu.getProgram(), cu.getMinAddress(), cpath, comment,
			row, col);
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#getFieldLocation(ghidra.app.util.viewer.field.ListingField, BigInteger, int, ghidra.program.util.ProgramLocation)
	 */
	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {
		if (!(programLoc instanceof CommentFieldLocation)) {
			return null;
		}

		CommentFieldLocation loc = (CommentFieldLocation) programLoc;
		if (loc.getCommentType() != CodeUnit.POST_COMMENT) {
			return null;
		}
		return new FieldLocation(index, fieldNum, loc.getRow(), loc.getCharOffset());
	}

	/**
	 * @see ghidra.app.util.viewer.field.FieldFactory#acceptsType(int, java.lang.Class)
	 */
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
		return new PostCommentFieldFactory(formatModel, provider, toolOptions, fieldOptions);
	}

	@Override
	public Color getDefaultColor() {
		return OptionsGui.COMMENT_POST.getDefaultColor();
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(FLAG_FUNCTION_EXIT_OPTION)) {
			flagFunctionExits = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(FLAG_TERMINATOR_OPTION)) {
			flagJMPsRETs = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(LINES_AFTER_BLOCKS_OPTION)) {
			nLinesAfterBlocks = ((Integer) newValue).intValue();
			if (nLinesAfterBlocks < 0) {
				nLinesAfterBlocks = 0;
			}
			model.update();
		}
		else if (optionName.equals(ENABLE_WORD_WRAP_MSG)) {
			isWordWrap = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG)) {
			alwaysShowAutomatic = ((Boolean) newValue).booleanValue();
		}
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		adjustAutomaticCommentDisplayOptions(options, optionName, oldValue, newValue);
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
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

	private ListingTextField getTextFieldForOptions(Instruction instr, String[] comments,
			String[] autoComment, ProxyObj<?> proxy, int xStart) {
		Listing listing = instr.getProgram().getListing();
		Address addr = instr.getMinAddress();
		FlowType flowType = instr.getFlowType();

		// Options that affect Post Comments:
		//   Flag Function Exits (only if post comment does not exist)
		//   Flag Jumps and Returns (only if post comment does not exist)
		//   Number of Lines After Block

		if (comments == null || comments.length == 0) {
			if (flagFunctionExits) {
				Function function = listing.getFunctionContaining(addr);
				if (function != null) {
					if (flagFunctionExits && (flowType.isTerminal())) {
						String[] str = new String[] {
							FUN_EXIT_FLAG_LEADER + function.getName() + FUN_EXIT_FLAG_TAIL };

						return getTextField(str, autoComment, proxy, xStart, true);
					}
				}
			}
			// Add Jump/Terminator
			if (flagJMPsRETs && !instr.hasFallthrough()) {
				String[] str = new String[] { DEFAULT_FLAG_COMMENT };
				return getTextField(str, autoComment, proxy, xStart, true);
			}
		}

		if (nLinesAfterBlocks > 0 || flagJMPsRETs) {
			// If this instruction is in a delay slot, then it is the end of a block.
			boolean endOfBlock = !instr.hasFallthrough() || instr.isInDelaySlot();

			if (endOfBlock && flagJMPsRETs && (comments == null || comments.length == 0)) {
				comments = new String[] { DEFAULT_FLAG_COMMENT };
			}
			if (!endOfBlock) {
				boolean deferEndOfBlock = false;
				CodeUnit nextCu = getNextCodeUnit(instr);
				if (nextCu instanceof Instruction) {
					Instruction nextInstr = (Instruction) nextCu;
					FlowType nextFlowType = nextInstr.getFlowType();
					deferEndOfBlock =
						(!nextInstr.hasFallthrough() || nextFlowType == RefType.CONDITIONAL_JUMP ||
							nextFlowType == RefType.CONDITIONAL_TERMINATOR);
				}
				if (!deferEndOfBlock && (flowType == RefType.CONDITIONAL_JUMP ||
					flowType == RefType.CONDITIONAL_TERMINATOR)) {
					endOfBlock = true;
				}
			}
			if (endOfBlock) {
				if (comments == null) {
					comments = EMPTY_STRING_ARRAY;
				}
				if (autoComment == null) {
					autoComment = EMPTY_STRING_ARRAY;
				}
				int nLinesAutoComment =
					(comments.length == 0 || alwaysShowAutomatic) ? autoComment.length : 0;
				AttributedString prototypeString =
					new AttributedString("prototype", color, getMetrics());
				FieldElement[] fields =
					new FieldElement[comments.length + nLinesAfterBlocks + nLinesAutoComment];
				if (fields.length > 0) {
					for (int i = 0; i < nLinesAutoComment; i++) {
						AttributedString as = new AttributedString(autoComment[i],
							automaticCommentColor, getMetrics(automaticCommentStyle), false, null);
						fields[i] = new TextFieldElement(as, i, 0);
					}
					for (int i = 0; i < comments.length; i++) {
						int index = nLinesAutoComment + i;
						fields[index] = CommentUtils.parseTextForAnnotations(comments[i],
							instr.getProgram(), prototypeString, index);
					}
					for (int i = fields.length - nLinesAfterBlocks; i < fields.length; i++) {
						// add blank lines for end-of-block
						AttributedString as = new AttributedString("", color, getMetrics());
						fields[i] = new TextFieldElement(as, i, 0);
					}
					return ListingTextField.createMultilineTextField(this, proxy, fields, xStart,
						width, Integer.MAX_VALUE, hlProvider);
				}
			}
		}
		return getTextField(comments, autoComment, proxy, xStart, false);
	}

	private ListingTextField getTextField(String[] comments, String[] autoComment,
			ProxyObj<?> proxy, int xStart, boolean useLinesAfterBlock) {

		if (comments == null) {
			comments = EMPTY_STRING_ARRAY;
		}
		if (autoComment == null) {
			autoComment = EMPTY_STRING_ARRAY;
		}
		// TODO: convoluted logic since str will not be user comment if useLinesAfterBlock is true
		int nLinesAutoComment =
			((comments.length == 0 && !useLinesAfterBlock) || alwaysShowAutomatic)
					? autoComment.length
					: 0;
		if (!useLinesAfterBlock && comments.length == 0 && nLinesAutoComment == 0) {
			return null;
		}

		CodeUnit cu = (CodeUnit) proxy.getObject();
		Program program = cu.getProgram();
		AttributedString prototypeString = new AttributedString("prototype", color, getMetrics());
		List<FieldElement> fields = new ArrayList<>();
		for (int i = 0; i < nLinesAutoComment; i++) {
			AttributedString as = new AttributedString(autoComment[i], automaticCommentColor,
				getMetrics(automaticCommentStyle), false, null);
			fields.add(new TextFieldElement(as, i, 0));
		}
		for (String comment : comments) {
			fields.add(CommentUtils.parseTextForAnnotations(comment, program, prototypeString,
				fields.size()));
		}
		if (isWordWrap) {
			fields = FieldUtils.wrap(fields, width);
		}
		if (useLinesAfterBlock) {
			for (int i = 0; i < nLinesAfterBlocks; i++) {
				AttributedString as = new AttributedString("", color, getMetrics());
				fields.add(new TextFieldElement(as, fields.size(), 0));
			}
		}
		FieldElement[] elements = fields.toArray(new FieldElement[fields.size()]);

		return ListingTextField.createMultilineTextField(this, proxy, elements, xStart, width,
			Integer.MAX_VALUE, hlProvider);
	}

	private void init(Options options) {
		options.registerOption(ENABLE_WORD_WRAP_MSG, false, null,
			"Enables word wrapping in the pre-comments field.  " +
				"If word wrapping is on, user enter" + " new lines are ignored and the entire " +
				"comment is displayed in paragraph form. " + " If word wrapping is off, comments" +
				" are displayed in line format however the user entered " +
				"them.  Lines that are too long for the field, are truncated.");

		options.registerOption(FLAG_FUNCTION_EXIT_OPTION, false, null,
			"Toggle for whether a post comment should be displayed " +
				"at the exit of a function.");
		options.registerOption(FLAG_TERMINATOR_OPTION, false, null,
			"Toggle for whether a post comment should be displayed " +
				"at a jump or a return instruction.");
		options.registerOption(LINES_AFTER_BLOCKS_OPTION, 0, null,
			"Number of lines to display in the post comment after a code block.");
		options.registerOption(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG, true, null,
			"Toggles the display of the automatic post-comment");

		isWordWrap = options.getBoolean(ENABLE_WORD_WRAP_MSG, false);
		alwaysShowAutomatic = options.getBoolean(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG, true);
		if (DEFAULT_FLAG_COMMENT != null) {
			return;
		}
		// Initialize dashed separator lines
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < 80; i++) {
			sb.append("-");
		}
		DEFAULT_FLAG_COMMENT = sb.toString();

	}

	/**
	 * Get the code unit immediately following the
	 * specified code unit.
	 * @param cu code unit
	 * @return the next code unit or null if not found.
	 */
	private CodeUnit getNextCodeUnit(CodeUnit cu) {
		CodeUnit next = null;
		try {
			Address nextAddr = cu.getMaxAddress().addNoWrap(1);
			if (nextAddr != null) {
				next = cu.getProgram().getListing().getCodeUnitAt(nextAddr);
			}
			return next;
		}
		catch (AddressOverflowException e) {
			// don't care
		}
		return null;
	}

	/**
	 * See {@link InstructionPcodeOverride#getOverridingReference(RefType)}
	 * See {@link ghidra.app.plugin.processors.sleigh.PcodeEmit#checkOverrides}
	 * @param inst instruction
	 * @param type reference type
	 * @return {@link OverrideCommentData} object corresponding to override comment 
	 * ({@code null} if no override comment)
	 */
	private OverrideCommentData getOverrideCommentData(Instruction inst, RefType type,
			PcodeOp[] pcodeOps, PcodeOverride pcodeOverride) {
		//first, check whether the pcode corresponding to inst has an appropriate op
		Set<Integer> ops = new HashSet<>();
		if (type.equals(RefType.CALL_OVERRIDE_UNCONDITIONAL)) {
			ops.add(PcodeOp.CALL);
			ops.add(PcodeOp.CALLIND);
		}
		else if (type.equals(RefType.JUMP_OVERRIDE_UNCONDITIONAL)) {
			ops.add(PcodeOp.BRANCH);
			ops.add(PcodeOp.CBRANCH);
		}
		else if (type.equals(RefType.CALLOTHER_OVERRIDE_CALL) ||
			type.equals(RefType.CALLOTHER_OVERRIDE_JUMP)) {
			ops.add(PcodeOp.CALLOTHER);
		}
		else {
			return null;
		}

		boolean hasAppropriatePcodeOp = false;

		//used to warn user that there are CALLOTHER ops at this instruction that are
		//not overridden
		boolean hasMultipleCallOthers = false;
		//used to report the name of the CALLOTHER op that is overridden
		String callOtherName = null;
		String outputWarningString = null;
		for (PcodeOp op : pcodeOps) {
			if (ops.contains(op.getOpcode())) {
				hasAppropriatePcodeOp = true;
				if (op.getOpcode() == PcodeOp.CALLOTHER) {
					if (callOtherName == null) {
						callOtherName = inst.getProgram().getLanguage().getUserDefinedOpName(
							(int) op.getInput(0).getOffset());
						if (op.getOutput() != null) {
							outputWarningString =
								"WARNING: Output of " + callOtherName +
									" destroyed by override!";
						}
					}
					else {
						hasMultipleCallOthers = true;
					}
				}
			}
		}
		if (!hasAppropriatePcodeOp) {
			return null;
		}

		//now check whether there is an active overriding reference of the appropriate type
		if (type.equals(RefType.CALL_OVERRIDE_UNCONDITIONAL)) {
			Address ref = pcodeOverride.getOverridingReference(type);
			if (ref != null) {
				return new OverrideCommentData(ref, null, false, outputWarningString);
			}
			return null;
		}
		if (type.equals(RefType.JUMP_OVERRIDE_UNCONDITIONAL)) {
			Address ref = pcodeOverride.getOverridingReference(type);
			if (ref != null) {
				return new OverrideCommentData(ref, null, false, outputWarningString);
			}
			return null;
		}
		if (type.equals(RefType.CALLOTHER_OVERRIDE_CALL)) {
			Address ref = pcodeOverride.getOverridingReference(type);
			if (ref != null) {
				return new OverrideCommentData(ref, callOtherName, hasMultipleCallOthers,
					outputWarningString);
			}
			return null;
		}
		//must be in the RefType.CALLOTHER_OVERRIDE_JUMP case
		Address ref = pcodeOverride.getOverridingReference(RefType.CALLOTHER_OVERRIDE_CALL);
		if (ref != null) {
			return null; //CALLOTHER_OVERRIDE_CALL overrides have precedence
		}
		ref = pcodeOverride.getOverridingReference(RefType.CALLOTHER_OVERRIDE_JUMP);
		if (ref == null) {
			return null;
		}
		return new OverrideCommentData(ref, callOtherName, hasMultipleCallOthers,
			outputWarningString);

	}

	private class OverrideCommentData {
		private Address overridingRef;
		private String overriddenCallOther;
		private boolean hasMultipleCallOthers;
		private String outputWarningString = null;

		OverrideCommentData(Address overridingRef, String overriddenCallOther,
				boolean multipleCallOthers, String outputWarningString) {
			this.overridingRef = overridingRef;
			this.overriddenCallOther = overriddenCallOther;
			this.hasMultipleCallOthers = multipleCallOthers;
			this.outputWarningString = outputWarningString;
		}

		Address getOverridingRef() {
			return overridingRef;
		}

		String getOverriddenCallOther() {
			return overriddenCallOther;
		}

		boolean hasMultipleCallOthers() {
			return hasMultipleCallOthers;
		}

		String getOutputWarningString() {
			return outputWarningString;
		}
	}

}
