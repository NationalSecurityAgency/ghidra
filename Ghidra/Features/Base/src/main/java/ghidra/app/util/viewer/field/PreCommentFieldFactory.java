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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.FieldUtils;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.viewer.field.ListingColors.CommentColors;
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.CommentFieldLocation;
import ghidra.program.util.ProgramLocation;

/**
 * Generates pre-comment fields.
 */
public class PreCommentFieldFactory extends FieldFactory {

	private static String[] EMPTY_STRING_ARRAY = new String[0];

	public static final String FIELD_NAME = "Pre-Comment";

	private final static String GROUP_TITLE = "Format Code";
	private final static String FIELD_GROUP_TITLE = "Pre-comments Field";
	public final static String ENABLE_WORD_WRAP_MSG =
		FIELD_GROUP_TITLE + Options.DELIMITER + FieldUtils.WORD_WRAP_OPTION_NAME;
	public final static String ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG =
		FIELD_GROUP_TITLE + Options.DELIMITER + "Always Show the Automatic Comment";

	final static String FLAG_FUNCTION_ENTRY_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Flag Function Entry";
	final static String FLAG_SUBROUTINE_ENTRY_OPTION =
		GROUP_TITLE + Options.DELIMITER + "Flag Subroutine Entry";

	static String FUNCTION_FLAG_COMMENT;
	static String SUBROUTINE_FLAG_COMMENT;

	private boolean flagFunctionEntry;
	private boolean flagSubroutineEntry;
	private boolean isWordWrap;
	private boolean alwaysShowAutomatic;
	private int automaticCommentStyle;

	/**
	 * Constructor
	 */
	public PreCommentFieldFactory() {
		super(FIELD_NAME);
	}

	/**
	 * Constructor
	 * @param model the model that the field belongs to.
	 * @param hlProvider the HightLightStringProvider.
	 * @param displayOptions the Options for display properties.
	 * @param fieldOptions the Options for field specific properties.
	 */
	private PreCommentFieldFactory(FieldFormatModel model, ListingHighlightProvider hlProvider,
			Options displayOptions, Options fieldOptions) {
		super(FIELD_NAME, model, hlProvider, displayOptions, fieldOptions);

		fieldOptions.registerOption(FLAG_FUNCTION_ENTRY_OPTION, false, null,
			"Toggles the display of a pre-comment for a function entry");
		fieldOptions.registerOption(FLAG_SUBROUTINE_ENTRY_OPTION, false, null,
			"Toggles the display of a pre-comment for a sub-routine entry");

		flagFunctionEntry = fieldOptions.getBoolean(FLAG_FUNCTION_ENTRY_OPTION, false);
		flagSubroutineEntry = fieldOptions.getBoolean(FLAG_SUBROUTINE_ENTRY_OPTION, false);

		automaticCommentStyle =
			displayOptions.getInt(OptionsGui.COMMENT_AUTO.getStyleOptionName(), -1);

		init(fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();
		if (!enabled || !(obj instanceof CodeUnit)) {
			return null;
		}
		int x = startX + varWidth;
		CodeUnit cu = (CodeUnit) obj;

		String[] autoComment = getAutoPreComments(cu);

		String[] comments = getDefinedPreComments(cu);

		return getTextField(comments, autoComment, proxy, x);
	}

	private String[] getDefinedPreComments(CodeUnit cu) {

		// Do not show comments for nested components that share the same address as their parent
		if (cu instanceof Data) {
			Data data = (Data) cu;
			int[] cpath = data.getComponentPath();
			if (cpath.length > 0) {
				if (cpath[cpath.length - 1] == 0) {
					return null;
				}
			}
		}

		return cu.getCommentAsArray(CodeUnit.PRE_COMMENT);
	}

	private String[] getAutoPreComments(CodeUnit cu) {
		if (cu instanceof Instruction) {
			return getInstructionAutoComments((Instruction) cu);
		}
		return getDataAutoComments((Data) cu);
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField bf) {
		Object obj = bf.getProxy().getObject();
		if (!(obj instanceof CodeUnit)) {
			return null;
		}
		CodeUnit cu = (CodeUnit) obj;
		String[] comment = cu.getCommentAsArray(CodeUnit.PRE_COMMENT);
		int[] cpath = null;
		if (cu instanceof Data) {
			cpath = ((Data) cu).getComponentPath();
		}
		return new CommentFieldLocation(cu.getProgram(), cu.getMinAddress(), cpath, comment,
			CodeUnit.PRE_COMMENT, row, col);
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation programLoc) {
		if (!(programLoc instanceof CommentFieldLocation)) {
			return null;
		}

		CommentFieldLocation loc = (CommentFieldLocation) programLoc;
		if (loc.getCommentType() != CodeUnit.PRE_COMMENT) {
			return null;
		}
		return new FieldLocation(index, fieldNum, loc.getRow(), loc.getCharOffset());
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
			ToolOptions toolOptions, ToolOptions fieldOptions) {
		return new PreCommentFieldFactory(formatModel, provider, toolOptions, fieldOptions);
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(FLAG_FUNCTION_ENTRY_OPTION)) {
			flagFunctionEntry = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(FLAG_SUBROUTINE_ENTRY_OPTION)) {
			flagSubroutineEntry = ((Boolean) newValue).booleanValue();
			model.update();
		}
		else if (optionName.equals(ENABLE_WORD_WRAP_MSG)) {
			isWordWrap = ((Boolean) newValue).booleanValue();
		}
		else if (optionName.equals(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG)) {
			alwaysShowAutomatic = ((Boolean) newValue).booleanValue();
		}
	}

	private String[] getInstructionAutoComments(Instruction instr) {
		Program program = instr.getProgram();
		Address addr = instr.getMinAddress();

		if (flagFunctionEntry) {
			Function function = program.getListing().getFunctionAt(addr);
			if (function != null) {
				return new String[] { FUNCTION_FLAG_COMMENT };
			}
		}
		if (flagSubroutineEntry) {
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
			if (symbol != null) {
				boolean isSubroutine = false;
				ReferenceIterator iter = program.getReferenceManager().getReferencesTo(addr);
				while (iter.hasNext()) {
					Reference ref = iter.next();
					// Check for Subroutine CALL
					RefType refType = ref.getReferenceType();
					if (refType == RefType.CONDITIONAL_CALL ||
						refType == RefType.UNCONDITIONAL_CALL) {
						isSubroutine = true;
						break;
					}
				}
				if (isSubroutine) {
					return new String[] { SUBROUTINE_FLAG_COMMENT };
				}
			}
		}
		return null;
	}

	private String[] getDataAutoComments(Data data) {
		return getPreceedingComponentAutoComment(data);
	}

	/**
	 * A composite which immediately precedes the current address may contain trailing zero-length 
	 * components which implicitly refer to this address and are not rendered by the opened composite.
	 * This comment is intended to convey the existence of such hidden components which correspond
	 * to addr.
	 * <br>
	 * NOTE: Implementation only provides comment for one trailing zero-length component.  This could
	 * be improved to return a comment for all applicable trailing zero-length components. 
	 * @param data data location whose pre-comment is currently be generated
	 * @return auto-comment or null
	 */
	private String[] getPreceedingComponentAutoComment(Data data) {

		// NOTE: A zero-length composite has a length of 1 which may cause it to improperly consume
		// the address location which actually corresponds to a trailing zero-length 
		// component.

		int levelsToIgnore = 0;
		String label = null;
		Address prevDataAddr = data.getMinAddress().previous();
		if (prevDataAddr == null) {
			return null;
		}

		int[] cpath = data.getComponentPath();
		if (cpath != null && cpath.length > 0) {
			// check previous sibling data within composite
			if (cpath[cpath.length - 1] <= 0) {
				return null; // case not handled
			}
			data = data.getParent().getComponent(cpath[cpath.length - 1] - 1);
			if (data == null || !data.isStructure()) {
				return null;
			}
			levelsToIgnore = cpath.length - 1;
		}
		else {
			Program p = data.getProgram();
			data = p.getListing().getDefinedDataContaining(prevDataAddr);
			if (data == null || !(data.isStructure() || data.isDynamic())) {  // FIXME!! refer to DynamicDataType which has components - Union?
				return null;
			}
			Symbol s = p.getSymbolTable().getPrimarySymbol(data.getAddress());
			label = s != null ? s.getName(true) : data.getDataType().getName();
		}

		DataTypeComponent lastDtc = null;
		while (true) {
			DataType dt = data.getDataType();

			if (dt instanceof Structure) {
				Structure struct = (Structure) dt;
				List<DataTypeComponent> components =
					struct.getComponentsContaining(struct.getLength());
				lastDtc = components.isEmpty() ? null : components.get(components.size() - 1);
			}
			else if (dt instanceof DynamicDataType) {
				DynamicDataType ddt = (DynamicDataType) dt;
				lastDtc = ddt.getComponentAt(data.getLength(), data);
				int lastDtcOrdinal = ddt.getNumComponents(data) - 1;
				if (lastDtc != null && lastDtc.getOrdinal() < lastDtcOrdinal) {
					lastDtc = ddt.getComponent(lastDtcOrdinal, data);
				}
			}

			if (lastDtc == null || lastDtc.getLength() == 0) {
				break;
			}

			Data component = data.getComponent(lastDtc.getOrdinal());
			if (component == null) {
				return null;
			}
			data = component;
		}

		if (lastDtc == null || lastDtc.isBitFieldComponent()) {
			return null;
		}

		return buildZeroLengthComponentAutoComment(lastDtc, data, levelsToIgnore, label);
	}

	private String[] buildZeroLengthComponentAutoComment(DataTypeComponent lastZeroLengthComponent,
			Data data, int levelsToIgnore, String label) {

		String fieldName = lastZeroLengthComponent.getFieldName();
		if (StringUtils.isEmpty(fieldName)) {
			fieldName = lastZeroLengthComponent.getDefaultFieldName();
		}

		StringBuilder flexName = new StringBuilder(fieldName);

		int[] cpath = data.getComponentPath();
		int cpathIndex = cpath != null ? cpath.length - 1 : -1;

		while (cpathIndex >= levelsToIgnore) {
			Data parent = data.getParent();
			Data component = parent.getComponent(cpath[cpathIndex--]);
			flexName.insert(0, component.getFieldName() + ".");
			data = component;
		}

		if (label != null) {
			flexName.insert(0, label + ".");
		}

		return new String[] { "Zero-length Component: " +
			lastZeroLengthComponent.getDataType().getName() + " " + flexName.toString() };
	}

	private ListingTextField getTextField(String[] comments, String[] autoComment,
			ProxyObj<?> proxy, int xStart) {

		if (comments == null) {
			comments = EMPTY_STRING_ARRAY;
		}
		if (autoComment == null) {
			autoComment = EMPTY_STRING_ARRAY;
		}

		int nLinesAutoComment =
			(comments.length == 0 || alwaysShowAutomatic) ? autoComment.length : 0;
		if (comments.length == 0 && nLinesAutoComment == 0) {
			return null;
		}

		CodeUnit cu = (CodeUnit) proxy.getObject();
		Program program = cu.getProgram();
		AttributedString prototypeString =
			new AttributedString("prototype", CommentColors.PRE, getMetrics());
		List<FieldElement> fields = new ArrayList<>();
		for (int i = 0; i < nLinesAutoComment; i++) {
			AttributedString as = new AttributedString(autoComment[i], CommentColors.AUTO,
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

		return ListingTextField.createMultilineTextField(this, proxy, fields, xStart, width,
			hlProvider);
	}

	private void init(Options options) {
		options.registerOption(ENABLE_WORD_WRAP_MSG, false, null,
			FieldUtils.WORD_WRAP_OPTION_DESCRIPTION);
		options.registerOption(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG, true, null,
			"Toggles the display of the automatic pre-comment");

		isWordWrap = options.getBoolean(ENABLE_WORD_WRAP_MSG, false);
		alwaysShowAutomatic = options.getBoolean(ENABLE_ALWAYS_SHOW_AUTOMATIC_MSG, true);
		if (FUNCTION_FLAG_COMMENT != null) {
			return;
		}
		StringBuffer sb = new StringBuffer();
		sb.append("\n");
		for (int i = 0; i < 20; i++) {
			sb.append("|");
		}
		sb.append(" FUNCTION ");
		for (int i = 0; i < 50; i++) {
			sb.append("|");
		}
		sb.append("\n");
		FUNCTION_FLAG_COMMENT = sb.toString();

		sb.setLength(0);
		sb.append("\n");
		for (int i = 0; i < 19; i++) {
			sb.append("|");
		}
		sb.append(" SUBROUTINE ");
		for (int i = 0; i < 49; i++) {
			sb.append("|");
		}
		sb.append("\n");
		SUBROUTINE_FLAG_COMMENT = sb.toString();

		// set descriptions on options
		options.registerOption(FLAG_SUBROUTINE_ENTRY_OPTION, false, null,
			"Toggle for whether a pre comment should be displayed " +
				"at the entry point of a subroutine.");
		options.registerOption(FLAG_FUNCTION_ENTRY_OPTION, false, null,
			"Toggle for whether a pre comment should be displayed " +
				"at the entry point of a function.");

	}

}
