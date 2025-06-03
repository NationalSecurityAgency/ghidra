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
package ghidra.feature.vt.gui.util;

import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.Options;

public class VTOptionDefines {

	// Accept Options
	public static final String ACCEPT_MATCH_OPTIONS_NAME = "Accept Match Options";
	public static final String AUTO_CREATE_IMPLIED_MATCH = ACCEPT_MATCH_OPTIONS_NAME +
		".Auto Create Implied Matches";
	public static final String APPLY_FUNCTION_NAME_ON_ACCEPT = ACCEPT_MATCH_OPTIONS_NAME +
		".Automatically Apply Function Name on Accept";
	public static final String APPLY_DATA_NAME_ON_ACCEPT = ACCEPT_MATCH_OPTIONS_NAME +
		".Automatically Apply Data Label on Accept";

	// Apply Options
	public static final String APPLY_MARKUP_OPTIONS_NAME = "Apply Markup Options";
	public static boolean DEFAULT_OPTION_FOR_IGNORE_INCOMPLETE_MARKUP_ITEMS = false;
	public static boolean DEFAULT_OPTION_FOR_IGNORE_EXCLUDED_MARKUP_ITEMS = false;
	public static boolean DEFAULT_OPTION_FOR_PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY = false;
	public static ReplaceDataChoices DEFAULT_OPTION_FOR_DATA_MATCH_DATA_TYPE =
		ReplaceDataChoices.REPLACE_UNDEFINED_DATA_ONLY;
	public static FunctionNameChoices DEFAULT_OPTION_FOR_FUNCTION_NAME =
		FunctionNameChoices.ADD_AS_PRIMARY;
	public static FunctionSignatureChoices DEFAULT_OPTION_FOR_FUNCTION_SIGNATURE =
		FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT;
	public static ParameterDataTypeChoices DEFAULT_OPTION_FOR_FUNCTION_RETURN_TYPE =
		ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY;
	public static ReplaceChoices DEFAULT_OPTION_FOR_INLINE = ReplaceChoices.REPLACE;
	public static ReplaceChoices DEFAULT_OPTION_FOR_NO_RETURN = ReplaceChoices.REPLACE;
	public static CallingConventionChoices DEFAULT_OPTION_FOR_CALLING_CONVENTION =
		CallingConventionChoices.SAME_LANGUAGE;
	public static ReplaceChoices DEFAULT_OPTION_FOR_CALL_FIXUP = ReplaceChoices.REPLACE;
	public static ReplaceChoices DEFAULT_OPTION_FOR_VAR_ARGS = ReplaceChoices.REPLACE;
	public static ParameterDataTypeChoices DEFAULT_OPTION_FOR_PARAMETER_DATA_TYPES =
		ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY;
	public static SourcePriorityChoices DEFAULT_OPTION_FOR_PARAMETER_NAMES =
		SourcePriorityChoices.PRIORITY_REPLACE;
	public static HighestSourcePriorityChoices DEFAULT_OPTION_FOR_HIGHEST_NAME_PRIORITY =
		HighestSourcePriorityChoices.USER_PRIORITY_HIGHEST;
	public static CommentChoices DEFAULT_OPTION_FOR_PARAMETER_COMMENTS =
		CommentChoices.APPEND_TO_EXISTING;
	public static LabelChoices DEFAULT_OPTION_FOR_LABELS = LabelChoices.ADD;
	public static CommentChoices DEFAULT_OPTION_FOR_PLATE_COMMENTS =
		CommentChoices.APPEND_TO_EXISTING;
	public static CommentChoices DEFAULT_OPTION_FOR_PRE_COMMENTS =
		CommentChoices.APPEND_TO_EXISTING;
	public static CommentChoices DEFAULT_OPTION_FOR_EOL_COMMENTS =
		CommentChoices.APPEND_TO_EXISTING;
	public static CommentChoices DEFAULT_OPTION_FOR_REPEATABLE_COMMENTS =
		CommentChoices.APPEND_TO_EXISTING;
	public static CommentChoices DEFAULT_OPTION_FOR_POST_COMMENTS =
		CommentChoices.APPEND_TO_EXISTING;

	public static final String FUNCTION_NAME = APPLY_MARKUP_OPTIONS_NAME + ".Function Name";
	public static final String FUNCTION_RETURN_TYPE = APPLY_MARKUP_OPTIONS_NAME +
		".Function Return Type";
	public static final String LABELS = APPLY_MARKUP_OPTIONS_NAME + ".Labels";
	public static final String PLATE_COMMENT = APPLY_MARKUP_OPTIONS_NAME + ".Plate Comment";
	public static final String PRE_COMMENT = APPLY_MARKUP_OPTIONS_NAME + ".Pre Comment";
	public static final String END_OF_LINE_COMMENT = APPLY_MARKUP_OPTIONS_NAME +
		".End of Line Comment";
	public static final String REPEATABLE_COMMENT = APPLY_MARKUP_OPTIONS_NAME +
		".Repeatable Comment";
	public static final String POST_COMMENT = APPLY_MARKUP_OPTIONS_NAME + ".Post Comment";
	public static final String DATA_MATCH_DATA_TYPE = APPLY_MARKUP_OPTIONS_NAME +
		".Data Match Data Type";
	public static final String FUNCTION_SIGNATURE = APPLY_MARKUP_OPTIONS_NAME +
		".Function Signature";
	public static final String CALLING_CONVENTION = APPLY_MARKUP_OPTIONS_NAME +
		".Function Calling Convention";
	public static final String INLINE = APPLY_MARKUP_OPTIONS_NAME + ".Function Inline";
	public static final String NO_RETURN = APPLY_MARKUP_OPTIONS_NAME + ".Function No Return";
	public static final String PARAMETER_DATA_TYPES = APPLY_MARKUP_OPTIONS_NAME +
		".Function Parameter Data Types";
	public static final String PARAMETER_NAMES = APPLY_MARKUP_OPTIONS_NAME +
		".Function Parameter Names";
	public static final String HIGHEST_NAME_PRIORITY = APPLY_MARKUP_OPTIONS_NAME +
		".Function Parameter Names Highest Name Priority";
	public static final String PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY =
		APPLY_MARKUP_OPTIONS_NAME + ".Function Parameter Names Replace If Same Priority";
	public static final String PARAMETER_COMMENTS = APPLY_MARKUP_OPTIONS_NAME +
		".Function Parameter Comments";
	public static final String VAR_ARGS = APPLY_MARKUP_OPTIONS_NAME + ".Function Var Args";
	public static final String CALL_FIXUP = APPLY_MARKUP_OPTIONS_NAME + ".Function Call Fixup";

	public static final String IGNORE_INCOMPLETE_MARKUP_ITEMS = APPLY_MARKUP_OPTIONS_NAME +
		".Set Incomplete Markup Items To Ignored";
	public static final String IGNORE_EXCLUDED_MARKUP_ITEMS = APPLY_MARKUP_OPTIONS_NAME +
		".Set Excluded Markup Items To Ignored";

	public final static String DISPLAY_APPLY_MARKUP_OPTIONS = APPLY_MARKUP_OPTIONS_NAME +
		Options.DELIMITER + "Display Apply Markup Options";

	// Auto VT Options
	public static final String AUTO_VT_OPTIONS_NAME = "Auto Version Tracking Options";

	public static final String AUTO_VT_SYMBOL_CORRELATOR = "Symbol Correlator Options";
	public static final String AUTO_VT_DATA_CORRELATOR = "Data Correlator Options";
	public static final String AUTO_VT_EXACT_FUNCTION_CORRELATORS =
		"Exact Function Correlators Options";
	public static final String AUTO_VT_DUPLICATE_FUNCTION_CORRELATOR =
		"Duplicate Function Correlator Options";
	public static final String AUTO_VT_REFERENCE_CORRELATORS =
		"Reference Correlators Options";
	public static final String AUTO_VT_IMPLIED_MATCH_CORRELATOR =
		"Implied Match Correlator Options";

	public static final String CREATE_IMPLIED_MATCHES_OPTION_TEXT = "Create Implied Matches";

	public static final String CREATE_IMPLIED_MATCHES_OPTION = AUTO_VT_OPTIONS_NAME +
		"." + CREATE_IMPLIED_MATCHES_OPTION_TEXT;

	public static final String RUN_EXACT_DATA_OPTION_TEXT = "Run Exact Data Correlator";
	public static final String RUN_EXACT_DATA_OPTION = AUTO_VT_OPTIONS_NAME +
		"." + RUN_EXACT_DATA_OPTION_TEXT;

	public static final String RUN_EXACT_SYMBOL_OPTION_TEXT = "Run Exact Symbol Correlator";
	public static final String RUN_EXACT_SYMBOL_OPTION = AUTO_VT_OPTIONS_NAME +
		"." + RUN_EXACT_SYMBOL_OPTION_TEXT;

	public static final String RUN_EXACT_FUNCTION_BYTES_OPTION_TEXT =
		"Run Exact Function Bytes Correlator";
	public static final String RUN_EXACT_FUNCTION_BYTES_OPTION = AUTO_VT_OPTIONS_NAME +
		"." + "Run Exact Function Bytes Correlator";

	public static final String RUN_EXACT_FUNCTION_INST_OPTION_TEXT =
		"Run Exact Function Instructions Correlators";
	public static final String RUN_EXACT_FUNCTION_INST_OPTION = AUTO_VT_OPTIONS_NAME +
		"." + RUN_EXACT_FUNCTION_INST_OPTION_TEXT;

	public static final String RUN_DUPE_FUNCTION_OPTION_TEXT = "Run Duplicate Function Correlator";
	public static final String RUN_DUPE_FUNCTION_OPTION = AUTO_VT_OPTIONS_NAME +
		"." + RUN_DUPE_FUNCTION_OPTION_TEXT;

	public static final String RUN_REF_CORRELATORS_OPTION_TEXT = "Run the Reference Correlators";
	public static final String RUN_REF_CORRELATORS_OPTION = AUTO_VT_OPTIONS_NAME +
		"." + RUN_REF_CORRELATORS_OPTION_TEXT;

	public static final String APPLY_IMPLIED_MATCHES_OPTION_TEXT = "Apply Implied Matches";

	public static final String APPLY_IMPLIED_MATCHES_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_IMPLIED_MATCH_CORRELATOR +
			"." + APPLY_IMPLIED_MATCHES_OPTION_TEXT;

	public static final String MIN_VOTES_OPTION_TEXT = "Minimum Votes Needed";
	public static final String MIN_VOTES_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_IMPLIED_MATCH_CORRELATOR +
			"." + MIN_VOTES_OPTION_TEXT;

	public static final String MAX_CONFLICTS_OPTION_TEXT = "Maximum Conflicts Allowed";
	public static final String MAX_CONFLICTS_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_IMPLIED_MATCH_CORRELATOR +
			"." + MAX_CONFLICTS_OPTION_TEXT;

	public static final String SYMBOL_CORRELATOR_MIN_LEN_OPTION_TEXT =
		"Symbol Correlator Minimum Symbol Length";
	public static final String SYMBOL_CORRELATOR_MIN_LEN_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_SYMBOL_CORRELATOR +
			"." + SYMBOL_CORRELATOR_MIN_LEN_OPTION_TEXT;

	public static final String DATA_CORRELATOR_MIN_LEN_OPTION_TEXT =
		"Data Correlator Minimum Data Length";
	public static final String DATA_CORRELATOR_MIN_LEN_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_DATA_CORRELATOR +
			"." + "Data Correlator Minimum Data Length";

	public static final String FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT =
		"Exact Function Correlators Minimum Function Length";
	public static final String FUNCTION_CORRELATOR_MIN_LEN_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_EXACT_FUNCTION_CORRELATORS +
			"." + FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT;

	public static final String DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT =
		"Duplicate Function Correlator Minimum Function Length";
	public static final String DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_DUPLICATE_FUNCTION_CORRELATOR +
			"." + DUPE_FUNCTION_CORRELATOR_MIN_LEN_OPTION_TEXT;

	public static final String REF_CORRELATOR_MIN_SCORE_OPTION_TEXT =
		"Reference Correlators Minimum Score";
	public static final String REF_CORRELATOR_MIN_SCORE_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_REFERENCE_CORRELATORS +
			"." + REF_CORRELATOR_MIN_SCORE_OPTION_TEXT;

	public static final String REF_CORRELATOR_MIN_CONF_OPTION_TEXT =
		"Reference Correlators Minimum Confidence";
	public static final String REF_CORRELATOR_MIN_CONF_OPTION =
		AUTO_VT_OPTIONS_NAME + "." + AUTO_VT_REFERENCE_CORRELATORS +
			"." + REF_CORRELATOR_MIN_CONF_OPTION_TEXT;
}
