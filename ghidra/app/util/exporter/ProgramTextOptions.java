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
package ghidra.app.util.exporter;

import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.OptionException;
import ghidra.framework.options.SaveState;

class ProgramTextOptions {

	final static String OPTION_WIDTH = "Width";
	final static String OPTION_WIDTH_ADDR = " Address ";
	final static String OPTION_WIDTH_BYTES = " Bytes ";
	final static String OPTION_WIDTH_PREMNEMONIC = " PreMnemonic ";
	final static String OPTION_WIDTH_MNEMONIC = " Mnemonic ";
	final static String OPTION_WIDTH_OPERAND = " Operand ";
	final static String OPTION_WIDTH_EOL = " End of Line ";
	final static String OPTION_WIDTH_LABEL = " Labels ";
	final static String OPTION_WIDTH_REF = " References ";
	final static String OPTION_WIDTH_DATA_FIELD = " Data Field Name ";

	final static String OPTION_SHOW = "Show";
	final static String OPTION_SHOW_COMMENTS = " Comments ";
	final static String OPTION_SHOW_PROPERTIES = " Properties ";
	final static String OPTION_SHOW_STRUCTURES = " Structures ";
	final static String OPTION_SHOW_UNDEFINED = " Undefined Data ";
	final static String OPTION_SHOW_REF_HEADER = " Ref Headers ";
	final static String OPTION_SHOW_BACK_REFS = " Back Refs ";
	final static String OPTION_SHOW_FORWARD_REFS = " Forward Refs ";
	final static String OPTION_SHOW_FUNCTIONS = " Functions ";
	final static String OPTION_SHOW_BLOCK_NAMES = " Block Names ";

	final static String OPTION_ADV = "Advanced";
	final static String OPTION_ADV_LABEL_SUFFIX = " Label Suffix ";
	final static String OPTION_ADV_COMMENT_SUFFIX = " Comment Prefix ";

	private final static int DEFAULT_ADDR_WIDTH = 16;
	private final static int DEFAULT_BYTES_WIDTH = 12;
	private final static int DEFAULT_LABEL_WIDTH = 30;
	private final static int DEFAULT_PREMNEMONIC_WIDTH = 4;
	private final static int DEFAULT_MNEMONIC_WIDTH = 12;
	private final static int DEFAULT_OPERAND_WIDTH = 40;
	private final static int DEFAULT_EOL_WIDTH = 40;
	private final static int DEFAULT_REF_HEADER_WIDTH = 13;
	private final static int DEFAULT_REF_WIDTH = 40;
	private final static int DEFAULT_STACK_VAR_PRENAME_WIDTH = 10;
	private final static int DEFAULT_STACK_VAR_NAME_WIDTH = 15;
	private final static int DEFAULT_STACK_VAR_DATATYPE_WIDTH = 15;
	private final static int DEFAULT_STACK_VAR_OFFSET_WIDTH = 8;
	private final static int DEFAULT_STACK_VAR_COMMENT_WIDTH = 20;
	private final static int DEFAULT_STACK_VAR_XREF_WIDTH = 50;
	private final static int DEFAULT_DATA_FIELD_NAME_WIDTH = 12;

	private final static String DEFAULT_LABEL_SUFFIX = ":";
	private final static String DEFAULT_COMMENT_PREFIX = ";";

	private boolean isHTML;

	private int addrWidth = DEFAULT_ADDR_WIDTH;
	private int bytesWidth = DEFAULT_BYTES_WIDTH;
	private int labelWidth = DEFAULT_LABEL_WIDTH;
	private int preMnemonicWidth = DEFAULT_PREMNEMONIC_WIDTH;
	private int mnemonicWidth = DEFAULT_MNEMONIC_WIDTH;
	private int operandWidth = DEFAULT_OPERAND_WIDTH;
	private int eolWidth = DEFAULT_EOL_WIDTH;
	private int refHeaderWidth = DEFAULT_REF_HEADER_WIDTH;
	private int refWidth = DEFAULT_REF_WIDTH;
	private int stackVarPrenameWidth = DEFAULT_STACK_VAR_PRENAME_WIDTH;
	private int stackVarNameWidth = DEFAULT_STACK_VAR_NAME_WIDTH;
	private int stackVarDataTypeWidth = DEFAULT_STACK_VAR_DATATYPE_WIDTH;
	private int stackVarOffsetWidth = DEFAULT_STACK_VAR_OFFSET_WIDTH;
	private int stackVarCommentWidth = DEFAULT_STACK_VAR_COMMENT_WIDTH;
	private int stackVarXrefWidth = DEFAULT_STACK_VAR_XREF_WIDTH;
	private int dataFieldNameWidth = DEFAULT_DATA_FIELD_NAME_WIDTH;

	private boolean showComments = true;
	private boolean showProperties = true;
	private boolean showStructures = true;
	private boolean showUndefinedData = true;
	private boolean showReferenceHeaders = true;
	private boolean showBackReferences = true;
	private boolean showForwardReferences = true;
	private boolean showFunctions = true;
	private boolean showBlockNameInOperands = true;

	private String labelSuffix = DEFAULT_LABEL_SUFFIX;
	private String commentPrefix = DEFAULT_COMMENT_PREFIX;

	ProgramTextOptions() {
	}

	List<Option> getOptions() {//TODO add right into list
		Option[] options = new Option[] {
			new Option(OPTION_WIDTH, OPTION_WIDTH_LABEL, new Integer(labelWidth)),
			new Option(OPTION_WIDTH, OPTION_WIDTH_ADDR, new Integer(addrWidth)),
			new Option(OPTION_WIDTH, OPTION_WIDTH_BYTES, new Integer(bytesWidth)),
			new Option(OPTION_WIDTH, OPTION_WIDTH_PREMNEMONIC, new Integer(preMnemonicWidth)),
			new Option(OPTION_WIDTH, OPTION_WIDTH_MNEMONIC, new Integer(mnemonicWidth)),
			new Option(OPTION_WIDTH, OPTION_WIDTH_OPERAND, new Integer(operandWidth)),
			new Option(OPTION_WIDTH, OPTION_WIDTH_EOL, new Integer(eolWidth)),
			new Option(OPTION_WIDTH, OPTION_WIDTH_REF, new Integer(refWidth)),
			new Option(OPTION_WIDTH, OPTION_WIDTH_DATA_FIELD, new Integer(dataFieldNameWidth)),

			new Option(OPTION_SHOW, OPTION_SHOW_COMMENTS, new Boolean(showComments)),
			new Option(OPTION_SHOW, OPTION_SHOW_PROPERTIES, new Boolean(showProperties)),
			new Option(OPTION_SHOW, OPTION_SHOW_STRUCTURES, new Boolean(showStructures)),
			new Option(OPTION_SHOW, OPTION_SHOW_UNDEFINED, new Boolean(showUndefinedData)),
			new Option(OPTION_SHOW, OPTION_SHOW_REF_HEADER, new Boolean(showReferenceHeaders)),
			new Option(OPTION_SHOW, OPTION_SHOW_BACK_REFS, new Boolean(showBackReferences)),
			new Option(OPTION_SHOW, OPTION_SHOW_FORWARD_REFS, new Boolean(showForwardReferences)),
			new Option(OPTION_SHOW, OPTION_SHOW_FUNCTIONS, new Boolean(showFunctions)),
			new Option(OPTION_SHOW, OPTION_SHOW_BLOCK_NAMES, new Boolean(showBlockNameInOperands)),

			new Option(OPTION_ADV, OPTION_ADV_LABEL_SUFFIX, labelSuffix),
			new Option(OPTION_ADV, OPTION_ADV_COMMENT_SUFFIX, commentPrefix), };
		List<Option> optionsList = new ArrayList<Option>();
		Collections.addAll(optionsList, options);
		return optionsList;
	}

	void setOptions(List<Option> options) throws OptionException {
		for (Option option : options) {
			boolean wasOptionHandled = true;
			String groupName = option.getGroup();
			String optionName = option.getName();
			try {
				if (groupName.equals(OPTION_WIDTH)) {
					int value = ((Integer) option.getValue()).intValue();

					if (optionName.equals(OPTION_WIDTH_LABEL)) {
						labelWidth = value;
					}
					else if (optionName.equals(OPTION_WIDTH_ADDR)) {
						addrWidth = value;
					}
					else if (optionName.equals(OPTION_WIDTH_BYTES)) {
						bytesWidth = value;
					}
					else if (optionName.equals(OPTION_WIDTH_PREMNEMONIC)) {
						preMnemonicWidth = value;
					}
					else if (optionName.equals(OPTION_WIDTH_MNEMONIC)) {
						mnemonicWidth = value;
					}
					else if (optionName.equals(OPTION_WIDTH_OPERAND)) {
						operandWidth = value;
					}
					else if (optionName.equals(OPTION_WIDTH_EOL)) {
						eolWidth = value;
					}
					else if (optionName.equals(OPTION_WIDTH_REF)) {
						refWidth = value;
					}
					else if (optionName.equals(OPTION_WIDTH_DATA_FIELD)) {
						dataFieldNameWidth = value;
					}
					else {
						wasOptionHandled = false;
					}
				}
				else if (groupName.equals(OPTION_SHOW)) {
					boolean value = ((Boolean) option.getValue()).booleanValue();

					if (optionName.equals(OPTION_SHOW_COMMENTS)) {
						showComments = value;
					}
					else if (optionName.equals(OPTION_SHOW_PROPERTIES)) {
						showProperties = value;
					}
					else if (optionName.equals(OPTION_SHOW_STRUCTURES)) {
						showStructures = value;
					}
					else if (optionName.equals(OPTION_SHOW_UNDEFINED)) {
						showUndefinedData = value;
					}
					else if (optionName.equals(OPTION_SHOW_REF_HEADER)) {
						showReferenceHeaders = value;
					}
					else if (optionName.equals(OPTION_SHOW_BACK_REFS)) {
						showBackReferences = value;
					}
					else if (optionName.equals(OPTION_SHOW_FORWARD_REFS)) {
						showForwardReferences = value;
					}
					else if (optionName.equals(OPTION_SHOW_FUNCTIONS)) {
						showFunctions = value;
					}
					else if (optionName.equals(OPTION_SHOW_BLOCK_NAMES)) {
						showBlockNameInOperands = value;
					}
					else {
						wasOptionHandled = false;
					}
				}
				else if (groupName.equals(OPTION_ADV)) {
					String value = (String) option.getValue();

					if (optionName.equals(OPTION_ADV_COMMENT_SUFFIX)) {
						commentPrefix = value;
					}
					else if (optionName.equals(OPTION_ADV_LABEL_SUFFIX)) {
						labelSuffix = value;
					}
					else {
						wasOptionHandled = false;
					}
				}

				if (!wasOptionHandled) {
					throw new OptionException(
						"Unknown option: " + optionName + " in group: " + groupName);
				}

				int len = addrWidth + bytesWidth + preMnemonicWidth + mnemonicWidth + operandWidth +
					eolWidth + dataFieldNameWidth + refWidth + labelWidth;
				if (len < 1) {
					throw new OptionException("Need some width values.");
				}
			}
			catch (ClassCastException e) {
				throw new OptionException(
					"Invalid value for " + optionName + " - " + option.getValue());
			}
		}
	}

	void writeConfigState(SaveState saveState) {
		saveState.putInt("ADDR_WIDTH", getAddrWidth());
		saveState.putInt("BYTES_WIDTH", getBytesWidth());
		saveState.putInt("LABEL_WIDTH", getLabelWidth());
		saveState.putInt("PREMNEMONIC_WIDTH", getPreMnemonicWidth());
		saveState.putInt("MNEMONIC_WIDTH", getMnemonicWidth());
		saveState.putInt("OPERAND_WIDTH", getOperandWidth());
		saveState.putInt("EOL_WIDTH", getEolWidth());
		saveState.putInt("REF_WIDTH", getRefWidth());
		saveState.putInt("DATA_FIELD_NAME_WIDTH", getDataFieldNameWidth());

		saveState.putString("LABEL_SUFFIX", getLabelSuffix());
		saveState.putString("COMMENT_PREFIX", getCommentPrefix());

		saveState.putBoolean("INCLUDE_BLOCKNAMES", isShowBlockNameInOperands());
	}

	void readConfigState(SaveState saveState) {
		// Get values from XML file.
		addrWidth = saveState.getInt("ADDR_WIDTH", DEFAULT_ADDR_WIDTH);
		bytesWidth = saveState.getInt("BYTES_WIDTH", DEFAULT_BYTES_WIDTH);
		labelWidth = saveState.getInt("LABEL_WIDTH", DEFAULT_LABEL_WIDTH);
		preMnemonicWidth = saveState.getInt("PREMNEMONIC_WIDTH", DEFAULT_PREMNEMONIC_WIDTH);
		mnemonicWidth = saveState.getInt("MNEMONIC_WIDTH", DEFAULT_MNEMONIC_WIDTH);
		operandWidth = saveState.getInt("OPERAND_WIDTH", DEFAULT_OPERAND_WIDTH);
		eolWidth = saveState.getInt("EOL_WIDTH", DEFAULT_EOL_WIDTH);
		refWidth = saveState.getInt("REF_WIDTH", DEFAULT_REF_WIDTH);
		dataFieldNameWidth =
			saveState.getInt("DATA_FIELD_NAME_WIDTH", DEFAULT_DATA_FIELD_NAME_WIDTH);

		labelSuffix = saveState.getString("LABEL_SUFFIX", DEFAULT_LABEL_SUFFIX);
		commentPrefix = saveState.getString("COMMENT_PREFIX", DEFAULT_COMMENT_PREFIX);

		showBlockNameInOperands = saveState.getBoolean("INCLUDE_BLOCKNAMES", true);
	}

	int getAddrWidth() {
		return addrWidth;
	}

	int getBytesWidth() {
		return bytesWidth;
	}

	int getDataFieldNameWidth() {
		return dataFieldNameWidth;
	}

	int getEolWidth() {
		return eolWidth;
	}

	int getLabelWidth() {
		return labelWidth;
	}

	int getMnemonicWidth() {
		return mnemonicWidth;
	}

	int getOperandWidth() {
		return operandWidth;
	}

	int getPreMnemonicWidth() {
		return preMnemonicWidth;
	}

	int getRefHeaderWidth() {
		return refHeaderWidth;
	}

	int getRefWidth() {
		return refWidth;
	}

	boolean isShowBackReferences() {
		return showBackReferences;
	}

	boolean isShowComments() {
		return showComments;
	}

	boolean isShowBlockNameInOperands() {
		return showBlockNameInOperands;
	}

	boolean isShowForwardReferences() {
		return showForwardReferences;
	}

	boolean isShowFunctions() {
		return showFunctions;
	}

	boolean isShowProperties() {
		return showProperties;
	}

	boolean isShowReferenceHeaders() {
		return showReferenceHeaders;
	}

	boolean isShowStructures() {
		return showStructures;
	}

	boolean isShowUndefinedData() {
		return showUndefinedData;
	}

	int getStackVarCommentWidth() {
		return stackVarCommentWidth;
	}

	int getStackVarDataTypeWidth() {
		return stackVarDataTypeWidth;
	}

	int getStackVarNameWidth() {
		return stackVarNameWidth;
	}

	int getStackVarOffsetWidth() {
		return stackVarOffsetWidth;
	}

	int getStackVarPreNameWidth() {
		return stackVarPrenameWidth;
	}

	int getStackVarXrefWidth() {
		return stackVarXrefWidth;
	}

	String getCommentPrefix() {
		return commentPrefix;
	}

	String getLabelSuffix() {
		return labelSuffix;
	}

	boolean isHTML() {
		return isHTML;
	}

	void setHTML(boolean b) {
		isHTML = b;
	}

	boolean isShowFunctionLabel() {
		return false;//TODO:
	}

	boolean isShowBlockName() {
		return showBlockNameInOperands;
	}
}
