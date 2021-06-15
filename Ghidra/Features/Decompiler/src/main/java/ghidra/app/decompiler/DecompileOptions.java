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
package ghidra.app.decompiler;

import static ghidra.GhidraOptions.*;

import java.awt.Color;
import java.awt.Font;
import java.awt.event.MouseEvent;

import ghidra.GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.CompilerSpec.EvaluationModelType;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.SystemUtilities;

/**
 * Configuration options for the decompiler
 * This stores the options and can create an XML
 * string to be sent to the decompiler process
 *
 *
 *
 */
public class DecompileOptions {
	private final static String PREDICATE_OPTIONSTRING = "Analysis.Simplify predication";
	private final static String PREDICATE_OPTIONDESCRIPTION =
		"If set, multiple conditionally executed instructions " +
			"depending on one predicate will be combined into a single if/else statement";
	private final static boolean PREDICATE_OPTIONDEFAULT = true;
	private boolean predicate;

	private final static String READONLY_OPTIONSTRING = "Analysis.Respect readonly flags";
	private final static String READONLY_OPTIONDESCRIPTION =
		"If set, this option causes the decompiler to treat " +
			"any values in memory marked read-only as constant values.";
	private final static boolean READONLY_OPTIONDEFAULT = true;
	private boolean readOnly;

	private final static String ELIMINATE_UNREACHABLE_OPTIONSTRING =
		"Analysis.Eliminate unreachable code";
	private final static String ELIMINATE_UNREACHABLE_OPTIONDESCRIPTION =
		"If set, branches and code that can never be executed are " + "eliminated as dead code";
	private final static boolean ELIMINATE_UNREACHABLE_OPTIONDEFAULT = true;
	private boolean eliminateUnreachable;

	private final static String SIMPLIFY_DOUBLEPRECISION_OPTIONSTRING =
		"Analysis.Simplify extended integer operations";
	private final static String SIMPLIFY_DOUBLEPRECISION_OPTIONDESCRIPTION =
		"If set, integer operations which are split into high and low pieces are " +
			"collapsed into a single logical operation";
	private final static boolean SIMPLIFY_DOUBLEPRECISION_OPTIONDEFAULT = true;
	private boolean simplifyDoublePrecision;

	private final static String IGNOREUNIMPL_OPTIONSTRING =
		"Analysis.Ignore unimplemented instructions";
	private final static String IGNOREUNIMPL_OPTIONDESCRIPTION =
		"If set, instructions which do not have a p-code translation implemented are " +
			"treated as if they do nothing (like a NOP)";
	private final static boolean IGNOREUNIMPL_OPTIONDEFAULT = false;	// Must match Architecture::resetDefaultsInternal
	private boolean ignoreunimpl;

	private final static String INFERCONSTPTR_OPTIONSTRING = "Analysis.Infer constant pointers";
	private final static String INFERCONSTPTR_OPTIONDESCRIPTION =
		"If set, constants which are not being explicitly used as pointers, but which can be interpreted " +
			"as a legitimate address, will still be treated as having a pointer datatype";
	private final static boolean INFERCONSTPTR_OPTIONDEFAULT = true;	// Must match Architecture::resetDefaultsInternal
	private boolean inferconstptr;

	private final static String ANALYZEFORLOOPS_OPTIONSTRING = "Analysis.Recover -for- loops";
	private final static String ANALYZEFORLOOPS_OPTIONDESCRIPTION =
		"If set, the decompiler attempts to recover for-loop variables, including their initializer, condition, " +
			"and incrementer statements. Loop variable bounds are displayed as a formal -for- loop header";
	private final static boolean ANALYZEFORLOOPS_OPTIONDEFAULT = true;	// Must match Architecture::resetDefaultsInternal
	private boolean analyzeForLoops;

	private final static String NULLTOKEN_OPTIONSTRING = "Display.Print 'NULL' for null pointers";
	private final static String NULLTOKEN_OPTIONDESCRIPTION =
		"If set, any zero valued pointer (null pointer) will " +
			"be printed using the token 'NULL'. Otherwise, a cast " +
			"of the number '0' is printed.";
	private final static boolean NULLTOKEN_OPTIONDEFAULT = false;		// Must match PrintC::resetDefaultsPrintC
	private boolean nullToken;

	private final static String INPLACEOP_OPTIONSTRING =
		"Analysis.Use inplace assignment operators";
	private final static String INPLACEOP_OPTIONDESCRIPTION =
		"If set the inplace assignment operators will be used " +
			"for appropriate expressions. '+='   '*='   '&='   '<<=' etc.";
	private final static boolean INPLACEOP_OPTIONDEFAULT = false;	// Must match PrintC::resetDefaultsPrintC
	private boolean inplaceTokens;

	private final static String ALIASBLOCK_OPTIONSTRING = "Analysis.Alias Blocking";
	private final static String ALIASBLOCK_OPTIONDESCRIPTION =
		"Specify which data-types prevent a pointer alias from reaching across them on the stack.";

	public enum AliasBlockEnum {

		None("none", "None"),
		Struct("struct", "Structures"),
		Array("array", "Arrays and Structures"),
		All("all", "All Data-types");

		private String label;
		private String optionString;

		private AliasBlockEnum(String optString, String label) {
			this.label = label;
			this.optionString = optString;
		}

		public String getOptionString() {
			return optionString;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	private final static AliasBlockEnum ALIASBLOCK_OPTIONDEFAULT = AliasBlockEnum.Array;	// Must match Architecture::resetDefaultsInternal
	private AliasBlockEnum aliasBlock;

	private final static String CONVENTION_OPTIONSTRING = "Display.Print calling convention name";
	private final static String CONVENTION_OPTIONDESCRIPTION =
		"If set, the names of callling conventions (which differ " +
			"from the default) will be printed as part of the function prototype.";
	private final static boolean CONVENTION_OPTIONDEFAULT = true;	// Must match PrintC::resetDefaultsPrintC
	private boolean conventionPrint;

	private final static String NOCAST_OPTIONSTRING = "Display.Disable printing of type casts";
	private final static String NOCAST_OPTIONDESCRIPTION =
		"If set, any C style type cast recovered by the decompiler will not be displayed. " +
			"The resulting C syntax may not parse correctly.";
	private final static boolean NOCAST_OPTIONDEFAULT = false;		// Must match PrintC::resetDefaultsPrintC
	private boolean noCastPrint;

	private final static String MAXWIDTH_OPTIONSTRING = "Display.Maximum characters in a code line";
	private final static String MAXWIDTH_OPTIONDESCRIPTION =
		"Maximum number of characters allowed per line before " + "before line breaks are forced.";
	private final static int MAXWIDTH_OPTIONDEFAULT = 100;	// Must match EmitPrettyPrint::resetDefaultsPrettyPrint
	private int maxwidth;

	private final static String INDENTWIDTH_OPTIONSTRING =
		"Display.Number of characters per indent level";
	private final static String INDENTWIDTH_OPTIONDESCRIPTION =
		"Number of characters indented for each level of control-flow " + "or scope nesting";
	private final static int INDENTWIDTH_OPTIONDEFAULT = 2;	// Must match EmitXml::resetDefaultsInternal
	private int indentwidth;

	private final static String COMMENTINDENT_OPTIONSTRING = "Display.Comment line indent level";
	private final static String COMMENTINDENT_OPTIONDESCRIPTION =
		"Number of characters each line of comments is indented";
	private final static int COMMENTINDENT_OPTIONDEFAULT = 20;	// Must match PrintLanguage::resetDefaultsInternal
	private int commentindent;

	private final static String COMMENTSTYLE_OPTIONSTRING = "Display.Comment style";
	private final static String COMMENTSTYLE_OPTIONDESCRIPTION =
		"Choice between either the C style comments /* */ or C++ style // ";
	public static final int SUGGESTED_DECOMPILE_TIMEOUT_SECS = 30;
	public static final int SUGGESTED_MAX_PAYLOAD_BYTES = 50;
	public static final int SUGGESTED_MAX_INSTRUCTIONS = 100000;		// Must match Architecture::resetDefaultsInternal

	public enum CommentStyleEnum {

		CStyle("/* C-style comments */"), CPPStyle("// C++-style comments");

		private String label;

		private CommentStyleEnum(String label) {
			this.label = label;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	private final static CommentStyleEnum COMMENTSTYLE_OPTIONDEFAULT = CommentStyleEnum.CStyle;	// Must match PrintC::resetDefaultsPrintC
	private CommentStyleEnum commentStyle;

	private final static String COMMENTPRE_OPTIONSTRING = "Display.Display PRE comments";
	private final static String COMMENTPRE_OPTIONDESCRIPTION =
		"If set, disassembly pre-instruction (PRE) comments are displayed " +
			"in the decompiler C output";
	private final static boolean COMMENTPRE_OPTIONDEFAULT = true;	// Must match PrintLanguage::resetDefaultsInternal
	private boolean commentPREInclude;

	private final static String COMMENTPLATE_OPTIONSTRING = "Display.Display PLATE comments";
	private final static String COMMENTPLATE_OPTIONDESCRIPTION =
		"If set, disassembly plate comments are displayed " + "in the decompiler C output";
	private final static boolean COMMENTPLATE_OPTIONDEFAULT = false;	// Must match PrintLanguage::resetDefaultsInternal
	private boolean commentPLATEInclude;

	private final static String COMMENTPOST_OPTIONSTRING = "Display.Display POST comments";
	private final static String COMMENTPOST_OPTIONDESCRIPTION =
		"If set, disassembly post-instruction (POST) comments are displayed " +
			"in the decompiler C output";
	private final static boolean COMMENTPOST_OPTIONDEFAULT = false;	// Must match PrintLanguage::resetDefaultsInternal
	private boolean commentPOSTInclude;

	private final static String COMMENTEOL_OPTIONSTRING = "Display.Display EOL comments";
	private final static String COMMENTEOL_OPTIONDESCRIPTION =
		"If set, disassembly end-of-line (EOL) comments are displayed " +
			"in the decompiler C output";
	private final static boolean COMMENTEOL_OPTIONDEFAULT = false;	// Must match PrintLanguage::resetDefaultsInternal
	private boolean commentEOLInclude;

	private final static String COMMENTWARN_OPTIONSTRING = "Display.Display Warning comments";
	private final static String COMMENTWARN_OPTIONDESCRIPTION =
		"If set, warnings generated by the decompiler embedded in the displayed " +
			"code as comments";
	private final static boolean COMMENTWARN_OPTIONDEFAULT = true;	// Must match PrintLanguage::resetDefaultsInternal
	private boolean commentWARNInclude;

	private final static String COMMENTHEAD_OPTIONSTRING = "Display.Display Header comment";
	private final static String COMMENTHEAD_OPTIONDESCRIPTION =
		"If set, the entry point plate comment is displayed as " + "a function header comment.";
	private final static boolean COMMENTHEAD_OPTIONDEFAULT = true;	// Must match PrintLanguage::resetDefaultsInternal
	private boolean commentHeadInclude;

	public enum NamespaceStrategy {
		Minimal("minimal", "Minimally"), All("all", "Always"), Never("none", "Never");

		private String label;
		private String optionString;

		private NamespaceStrategy(String optString, String label) {
			this.label = label;
			this.optionString = optString;
		}

		public String getOptionString() {
			return optionString;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	private final static String NAMESPACE_OPTIONSTRING = "Display.Display Namespaces";
	private final static String NAMESPACE_OPTIONDESCRIPTION =
		"Choose how/if namespace tokens should be displayed along with symbol names";
	private final static NamespaceStrategy NAMESPACE_OPTIONDEFAULT = NamespaceStrategy.Minimal;	// Must match PrintLanguage::resetDefaultsInternal
	private NamespaceStrategy namespaceStrategy;

	private final static String INTEGERFORMAT_OPTIONSTRING = "Display.Integer format";
	private final static String INTEGERFORMAT_OPTIONDESCRIPTION =
		"Choose how to display integers: as hexadecimal, decimal, or best fit";

	public enum IntegerFormatEnum {

		Hexadecimal("hex", "Force Hexadecimal"),
		Decimal("dec", "Force Decimal"),
		BestFit("best", "Best Fit");

		private String label;
		private String optionString;

		private IntegerFormatEnum(String optString, String label) {
			this.label = label;
			this.optionString = optString;
		}

		public String getOptionString() {
			return optionString;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	private final static IntegerFormatEnum INTEGERFORMAT_OPTIONDEFAULT = IntegerFormatEnum.BestFit;		// Must match PrintLanguage::resetDefaultsInternal
	private IntegerFormatEnum integerFormat;

	private final static Color HIGHLIGHT_MIDDLE_MOUSE_DEF = new Color(255, 255, 0, 128);
	private Color middleMouseHighlightColor;
	private int middleMouseHighlightButton = MouseEvent.BUTTON2;

	private final static String HIGHLIGHT_CURRENT_VARIABLE_MSG =
		"Display.Color for Current Variable Highlight";
	private final static Color HIGHLIGHT_CURRENT_VARIABLE_DEF = new Color(255, 255, 0, 128);
	private Color currentVariableHighlightColor;

	private final static String HIGHLIGHT_KEYWORD_MSG = "Display.Color for Keywords";
	private final static Color HIGHLIGHT_KEYWORD_DEF = Color.decode("0x0001E6");
	private Color keywordColor;
	private final static String HIGHLIGHT_FUNCTION_MSG = "Display.Color for Function names";
	private final static Color HIGHLIGHT_FUNCTION_DEF = Color.decode("0x0000FF");
	private Color functionColor;
	private final static String HIGHLIGHT_COMMENT_MSG = "Display.Color for Comments";
	private final static Color HIGHLIGHT_COMMENT_DEF = Color.decode("0x9600FF");
	private Color commentColor;
	private final static String HIGHLIGHT_VARIABLE_MSG = "Display.Color for Variables";
	private final static Color HIGHLIGHT_VARIABLE_DEF = Color.decode("0x999900");
	private Color variableColor;
	private final static String HIGHLIGHT_CONST_MSG = "Display.Color for Constants";
	private final static Color HIGHLIGHT_CONST_DEF = Color.decode("0x008E00");
	private Color constantColor;
	private final static String HIGHLIGHT_TYPE_MSG = "Display.Color for Types";
	private final static Color HIGHLIGHT_TYPE_DEF = Color.decode("0x0033CC");
	private Color typeColor;
	private final static String HIGHLIGHT_PARAMETER_MSG = "Display.Color for Parameters";
	private final static Color HIGHLIGHT_PARAMETER_DEF = Color.decode("0x9B009B");
	private Color parameterColor;
	private final static String HIGHLIGHT_GLOBAL_MSG = "Display.Color for Globals";
	private final static Color HIGHLIGHT_GLOBAL_DEF = Color.decode("0x009999");
	private Color globalColor;
	private final static String HIGHLIGHT_DEFAULT_MSG = "Display.Color Default";
	private final static Color HIGHLIGHT_DEFAULT_DEF = Color.BLACK;
	private Color defaultColor;

	private static final String CODE_VIEWER_BACKGROUND_COLOR_MSG = "Display.Background Color";
	private static final Color CODE_VIEWER_BACKGROUND_COLOR = Color.WHITE;
	private Color codeViewerBackgroundColor;

	private static final String SEARCH_HIGHLIGHT_MSG =
		"Display.Color for Highlighting Find Matches";
	private static final Color SEARCH_HIGHLIGHT_DEF = new Color(100, 100, 255);
	private Color defaultSearchHighlightColor = SEARCH_HIGHLIGHT_DEF;

	final static String FONT_MSG = "Display.Font";
	final static Font DEFAULT_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 12);
	private Font defaultFont;

	private final static String CACHED_RESULTS_SIZE_MSG = "Cache Size (Functions)";
	private final static int SUGGESTED_CACHED_RESULTS_SIZE = 10;
	private final static String CACHE_RESULTS_DESCRIPTION =
		"Number of Decompiled Functions to Cache in the Decompile Window";

	private final static String LINE_NUMBER_MSG = "Display.Display Line Numbers";
	private final static String DECOMPILE_TIMEOUT = "Decompiler Timeout (seconds)";
	private final static String PAYLOAD_LIMIT = "Decompiler Max-Payload (MBytes)";
	private final static String MAX_INSTRUCTIONS = "Max Instructions per Function";
	private final static Boolean LINE_NUMBER_DEF = Boolean.TRUE;
	private boolean displayLineNumbers;
	private int decompileTimeoutSeconds;
	private int payloadLimitMBytes;
	private int maxIntructionsPer;
	private int cachedResultsSize;

	private DecompilerLanguage displayLanguage; // Output language displayed by the decompiler

	private String protoEvalModel; // Name of the prototype evaluation model

	public DecompileOptions() {
		predicate = PREDICATE_OPTIONDEFAULT;
		readOnly = READONLY_OPTIONDEFAULT; // This flipped values
		eliminateUnreachable = ELIMINATE_UNREACHABLE_OPTIONDEFAULT;
		simplifyDoublePrecision = SIMPLIFY_DOUBLEPRECISION_OPTIONDEFAULT;
		ignoreunimpl = IGNOREUNIMPL_OPTIONDEFAULT;
		inferconstptr = INFERCONSTPTR_OPTIONDEFAULT;
		analyzeForLoops = ANALYZEFORLOOPS_OPTIONDEFAULT;
		nullToken = NULLTOKEN_OPTIONDEFAULT;
		inplaceTokens = INPLACEOP_OPTIONDEFAULT;
		aliasBlock = ALIASBLOCK_OPTIONDEFAULT;
		conventionPrint = CONVENTION_OPTIONDEFAULT;
		noCastPrint = NOCAST_OPTIONDEFAULT;
		maxwidth = MAXWIDTH_OPTIONDEFAULT;
		indentwidth = INDENTWIDTH_OPTIONDEFAULT;
		commentindent = COMMENTINDENT_OPTIONDEFAULT;
		commentStyle = COMMENTSTYLE_OPTIONDEFAULT;
		commentPREInclude = COMMENTPRE_OPTIONDEFAULT;
		commentPLATEInclude = COMMENTPLATE_OPTIONDEFAULT;
		commentPOSTInclude = COMMENTPOST_OPTIONDEFAULT;
		commentEOLInclude = COMMENTEOL_OPTIONDEFAULT;
		commentWARNInclude = COMMENTWARN_OPTIONDEFAULT;
		commentHeadInclude = COMMENTHEAD_OPTIONDEFAULT;
		namespaceStrategy = NAMESPACE_OPTIONDEFAULT;
		integerFormat = INTEGERFORMAT_OPTIONDEFAULT;
		keywordColor = HIGHLIGHT_KEYWORD_DEF;
		functionColor = HIGHLIGHT_FUNCTION_DEF;
		commentColor = HIGHLIGHT_COMMENT_DEF;
		variableColor = HIGHLIGHT_VARIABLE_DEF;
		constantColor = HIGHLIGHT_CONST_DEF;
		typeColor = HIGHLIGHT_TYPE_DEF;
		parameterColor = HIGHLIGHT_PARAMETER_DEF;
		globalColor = HIGHLIGHT_GLOBAL_DEF;
		defaultColor = HIGHLIGHT_DEFAULT_DEF;
		codeViewerBackgroundColor = CODE_VIEWER_BACKGROUND_COLOR;
		defaultFont = DEFAULT_FONT;
		displayLineNumbers = LINE_NUMBER_DEF;
		displayLanguage = ProgramCompilerSpec.DECOMPILER_OUTPUT_DEF;
		protoEvalModel = "default";
		decompileTimeoutSeconds = SUGGESTED_DECOMPILE_TIMEOUT_SECS;
		payloadLimitMBytes = SUGGESTED_MAX_PAYLOAD_BYTES;
		maxIntructionsPer = SUGGESTED_MAX_INSTRUCTIONS;
		cachedResultsSize = SUGGESTED_CACHED_RESULTS_SIZE;
	}

	/**
	 * Grab all the decompiler options from various sources within a specific tool and program
	 * and cache them in this object.
	 * @param ownerPlugin  the plugin that owns the "tool options" for the decompiler
	 * @param opt          the Options object that contains the "tool options" specific to the decompiler
	 * @param program      the program whose "program options" are relevant to the decompiler
	 */
	public void grabFromToolAndProgram(Plugin ownerPlugin, ToolOptions opt, Program program) {

		grabFromProgram(program);

		// assuming if one is not registered, then none area
		if (!opt.isRegistered(PREDICATE_OPTIONSTRING)) {
			return;
		}

		predicate = opt.getBoolean(PREDICATE_OPTIONSTRING, PREDICATE_OPTIONDEFAULT);
		readOnly = opt.getBoolean(READONLY_OPTIONSTRING, READONLY_OPTIONDEFAULT);
		eliminateUnreachable =
			opt.getBoolean(ELIMINATE_UNREACHABLE_OPTIONSTRING, ELIMINATE_UNREACHABLE_OPTIONDEFAULT);
		simplifyDoublePrecision = opt.getBoolean(SIMPLIFY_DOUBLEPRECISION_OPTIONSTRING,
			SIMPLIFY_DOUBLEPRECISION_OPTIONDEFAULT);
		ignoreunimpl = opt.getBoolean(IGNOREUNIMPL_OPTIONSTRING, IGNOREUNIMPL_OPTIONDEFAULT);
		inferconstptr = opt.getBoolean(INFERCONSTPTR_OPTIONSTRING, INFERCONSTPTR_OPTIONDEFAULT);
		analyzeForLoops =
			opt.getBoolean(ANALYZEFORLOOPS_OPTIONSTRING, ANALYZEFORLOOPS_OPTIONDEFAULT);
		nullToken = opt.getBoolean(NULLTOKEN_OPTIONSTRING, NULLTOKEN_OPTIONDEFAULT);
		inplaceTokens = opt.getBoolean(INPLACEOP_OPTIONSTRING, INPLACEOP_OPTIONDEFAULT);
		aliasBlock = opt.getEnum(ALIASBLOCK_OPTIONSTRING, ALIASBLOCK_OPTIONDEFAULT);
		conventionPrint = opt.getBoolean(CONVENTION_OPTIONSTRING, CONVENTION_OPTIONDEFAULT);
		noCastPrint = opt.getBoolean(NOCAST_OPTIONSTRING, NOCAST_OPTIONDEFAULT);
		maxwidth = opt.getInt(MAXWIDTH_OPTIONSTRING, MAXWIDTH_OPTIONDEFAULT);
		indentwidth = opt.getInt(INDENTWIDTH_OPTIONSTRING, INDENTWIDTH_OPTIONDEFAULT);
		commentindent = opt.getInt(COMMENTINDENT_OPTIONSTRING, COMMENTINDENT_OPTIONDEFAULT);
		commentStyle = opt.getEnum(COMMENTSTYLE_OPTIONSTRING, COMMENTSTYLE_OPTIONDEFAULT);
		commentEOLInclude = opt.getBoolean(COMMENTEOL_OPTIONSTRING, COMMENTEOL_OPTIONDEFAULT);
		commentPREInclude = opt.getBoolean(COMMENTPRE_OPTIONSTRING, COMMENTPRE_OPTIONDEFAULT);
		commentPOSTInclude = opt.getBoolean(COMMENTPOST_OPTIONSTRING, COMMENTPOST_OPTIONDEFAULT);
		commentPLATEInclude = opt.getBoolean(COMMENTPLATE_OPTIONSTRING, COMMENTPLATE_OPTIONDEFAULT);
		commentWARNInclude = opt.getBoolean(COMMENTWARN_OPTIONSTRING, COMMENTWARN_OPTIONDEFAULT);
		commentHeadInclude = opt.getBoolean(COMMENTHEAD_OPTIONSTRING, COMMENTHEAD_OPTIONDEFAULT);
		namespaceStrategy = opt.getEnum(NAMESPACE_OPTIONSTRING, NAMESPACE_OPTIONDEFAULT);
		integerFormat = opt.getEnum(INTEGERFORMAT_OPTIONSTRING, INTEGERFORMAT_OPTIONDEFAULT);
		keywordColor = opt.getColor(HIGHLIGHT_KEYWORD_MSG, HIGHLIGHT_KEYWORD_DEF);
		typeColor = opt.getColor(HIGHLIGHT_TYPE_MSG, HIGHLIGHT_TYPE_DEF);
		functionColor = opt.getColor(HIGHLIGHT_FUNCTION_MSG, HIGHLIGHT_FUNCTION_DEF);
		commentColor = opt.getColor(HIGHLIGHT_COMMENT_MSG, HIGHLIGHT_COMMENT_DEF);
		variableColor = opt.getColor(HIGHLIGHT_VARIABLE_MSG, HIGHLIGHT_VARIABLE_DEF);
		constantColor = opt.getColor(HIGHLIGHT_CONST_MSG, HIGHLIGHT_CONST_DEF);
		parameterColor = opt.getColor(HIGHLIGHT_PARAMETER_MSG, HIGHLIGHT_PARAMETER_DEF);
		globalColor = opt.getColor(HIGHLIGHT_GLOBAL_MSG, HIGHLIGHT_GLOBAL_DEF);
		defaultColor = opt.getColor(HIGHLIGHT_DEFAULT_MSG, HIGHLIGHT_DEFAULT_DEF);
		codeViewerBackgroundColor =
			opt.getColor(CODE_VIEWER_BACKGROUND_COLOR_MSG, CODE_VIEWER_BACKGROUND_COLOR);
		currentVariableHighlightColor =
			opt.getColor(HIGHLIGHT_CURRENT_VARIABLE_MSG, HIGHLIGHT_CURRENT_VARIABLE_DEF);
		defaultFont = opt.getFont(FONT_MSG, DEFAULT_FONT);
		defaultFont = SystemUtilities.adjustForFontSizeOverride(defaultFont);
		defaultSearchHighlightColor = opt.getColor(SEARCH_HIGHLIGHT_MSG, SEARCH_HIGHLIGHT_DEF);
		displayLineNumbers = opt.getBoolean(LINE_NUMBER_MSG, LINE_NUMBER_DEF);
		decompileTimeoutSeconds = opt.getInt(DECOMPILE_TIMEOUT, SUGGESTED_DECOMPILE_TIMEOUT_SECS);
		payloadLimitMBytes = opt.getInt(PAYLOAD_LIMIT, SUGGESTED_MAX_PAYLOAD_BYTES);
		maxIntructionsPer = opt.getInt(MAX_INSTRUCTIONS, SUGGESTED_MAX_INSTRUCTIONS);
		cachedResultsSize = opt.getInt(CACHED_RESULTS_SIZE_MSG, SUGGESTED_CACHED_RESULTS_SIZE);

		grabFromToolOptions(ownerPlugin);
	}

	private void grabFromToolOptions(Plugin ownerPlugin) {
		if (ownerPlugin == null) {
			return;
		}

		PluginTool tool = ownerPlugin.getTool();
		Options toolOptions = tool.getOptions(CATEGORY_BROWSER_FIELDS);

		middleMouseHighlightColor =
			toolOptions.getColor(HIGHLIGHT_COLOR_NAME, HIGHLIGHT_MIDDLE_MOUSE_DEF);

		CURSOR_MOUSE_BUTTON_NAMES mouseEvent =
			toolOptions.getEnum(CURSOR_HIGHLIGHT_BUTTON_NAME, CURSOR_MOUSE_BUTTON_NAMES.MIDDLE);
		middleMouseHighlightButton = mouseEvent.getMouseEventID();
	}

	/**
	 * Grab all the decompiler options from the program specifically
	 * and cache them in this object.
	 * @param program      the program whose "program options" are relevant to the decompiler
	 */
	public void grabFromProgram(Program program) {
		// Default values, even if there is no program
		displayLanguage = ProgramCompilerSpec.DECOMPILER_OUTPUT_DEF;
		protoEvalModel = "default";
		if (program == null) {
			return;
		}

		CompilerSpec cspec = program.getCompilerSpec();
		PrototypeModel model = cspec.getPrototypeEvaluationModel(EvaluationModelType.EVAL_CURRENT);
		if (model != null) {
			String modelname = model.getName();
			if (modelname != null) {
				protoEvalModel = modelname;
			}
		}
		displayLanguage = cspec.getDecompilerOutputLanguage();
	}

	public String getProtoEvalModel() {
		return protoEvalModel;
	}

	public void setProtoEvalModel(String protoEvalModel) {
		this.protoEvalModel = protoEvalModel;
	}

	/**
	 * This registers all the decompiler tool options with ghidra, and has the side effect of
	 * pulling all the current values for the options if they exist
	 * @param ownerPlugin  the plugin to which the options should be registered
	 * @param opt          the options object to register with
	 * @param program      the program
	 */
	public void registerOptions(Plugin ownerPlugin, ToolOptions opt, Program program) {
		opt.registerOption(PREDICATE_OPTIONSTRING, PREDICATE_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisPredicate"),
			PREDICATE_OPTIONDESCRIPTION);
		opt.registerOption(READONLY_OPTIONSTRING, READONLY_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisReadOnly"),
			READONLY_OPTIONDESCRIPTION);
		opt.registerOption(ELIMINATE_UNREACHABLE_OPTIONSTRING, ELIMINATE_UNREACHABLE_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisUnreachable"),
			ELIMINATE_UNREACHABLE_OPTIONDESCRIPTION);
		opt.registerOption(SIMPLIFY_DOUBLEPRECISION_OPTIONSTRING,
			SIMPLIFY_DOUBLEPRECISION_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisExtendedPrecision"),
			SIMPLIFY_DOUBLEPRECISION_OPTIONDESCRIPTION);
		opt.registerOption(IGNOREUNIMPL_OPTIONSTRING, IGNOREUNIMPL_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisIgnoreUnimplemented"),
			IGNOREUNIMPL_OPTIONDESCRIPTION);
		opt.registerOption(INFERCONSTPTR_OPTIONSTRING, INFERCONSTPTR_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisInferConstants"),
			INFERCONSTPTR_OPTIONDESCRIPTION);
		opt.registerOption(ANALYZEFORLOOPS_OPTIONSTRING, ANALYZEFORLOOPS_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisForLoops"),
			ANALYZEFORLOOPS_OPTIONDESCRIPTION);
		opt.registerOption(NULLTOKEN_OPTIONSTRING, NULLTOKEN_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayNull"), NULLTOKEN_OPTIONDESCRIPTION);
		opt.registerOption(INPLACEOP_OPTIONSTRING, INPLACEOP_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisInPlace"),
			INPLACEOP_OPTIONDESCRIPTION);
		opt.registerOption(ALIASBLOCK_OPTIONSTRING, ALIASBLOCK_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisAliasBlocking"),
			ALIASBLOCK_OPTIONDESCRIPTION);
		opt.registerOption(CONVENTION_OPTIONSTRING, CONVENTION_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayConvention"),
			CONVENTION_OPTIONDESCRIPTION);
		opt.registerOption(NOCAST_OPTIONSTRING, NOCAST_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayDisableCasts"),
			NOCAST_OPTIONDESCRIPTION);
		opt.registerOption(MAXWIDTH_OPTIONSTRING, MAXWIDTH_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayMaxChar"), MAXWIDTH_OPTIONDESCRIPTION);
		opt.registerOption(INDENTWIDTH_OPTIONSTRING, INDENTWIDTH_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayIndentLevel"),
			INDENTWIDTH_OPTIONDESCRIPTION);
		opt.registerOption(COMMENTINDENT_OPTIONSTRING, COMMENTINDENT_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayCommentIndent"),
			COMMENTINDENT_OPTIONDESCRIPTION);
		opt.registerOption(COMMENTSTYLE_OPTIONSTRING, COMMENTSTYLE_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayCommentStyle"),
			COMMENTSTYLE_OPTIONDESCRIPTION);
		opt.registerOption(COMMENTEOL_OPTIONSTRING, COMMENTEOL_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "CommentOptions"),
			COMMENTEOL_OPTIONDESCRIPTION);
		opt.registerOption(COMMENTPRE_OPTIONSTRING, COMMENTPRE_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "CommentOptions"),
			COMMENTPRE_OPTIONDESCRIPTION);
		opt.registerOption(COMMENTPOST_OPTIONSTRING, COMMENTPOST_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "CommentOptions"),
			COMMENTPOST_OPTIONDESCRIPTION);
		opt.registerOption(COMMENTPLATE_OPTIONSTRING, COMMENTPLATE_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "CommentOptions"),
			COMMENTPLATE_OPTIONDESCRIPTION);
		opt.registerOption(COMMENTWARN_OPTIONSTRING, COMMENTWARN_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayWarningComments"),
			COMMENTWARN_OPTIONDESCRIPTION);
		opt.registerOption(COMMENTHEAD_OPTIONSTRING, COMMENTHEAD_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayHeaderComment"),
			COMMENTHEAD_OPTIONDESCRIPTION);
		opt.registerOption(NAMESPACE_OPTIONSTRING, NAMESPACE_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayNamespaces"),
			NAMESPACE_OPTIONDESCRIPTION);
		opt.registerOption(INTEGERFORMAT_OPTIONSTRING, INTEGERFORMAT_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayIntegerFormat"),
			INTEGERFORMAT_OPTIONDESCRIPTION);
		opt.registerOption(HIGHLIGHT_KEYWORD_MSG, HIGHLIGHT_KEYWORD_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting keywords.");
		opt.registerOption(HIGHLIGHT_TYPE_MSG, HIGHLIGHT_TYPE_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting types.");
		opt.registerOption(HIGHLIGHT_FUNCTION_MSG, HIGHLIGHT_FUNCTION_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting function names.");
		opt.registerOption(HIGHLIGHT_COMMENT_MSG, HIGHLIGHT_COMMENT_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting comments.");
		opt.registerOption(HIGHLIGHT_VARIABLE_MSG, HIGHLIGHT_VARIABLE_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting variables.");
		opt.registerOption(HIGHLIGHT_CONST_MSG, HIGHLIGHT_CONST_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting constants.");
		opt.registerOption(HIGHLIGHT_PARAMETER_MSG, HIGHLIGHT_PARAMETER_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting parameters.");
		opt.registerOption(HIGHLIGHT_GLOBAL_MSG, HIGHLIGHT_GLOBAL_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting global variables.");
		opt.registerOption(HIGHLIGHT_DEFAULT_MSG, HIGHLIGHT_DEFAULT_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayColorDefault"),
			"The color used when a specific color is not specified.");
		opt.registerOption(CODE_VIEWER_BACKGROUND_COLOR_MSG, CODE_VIEWER_BACKGROUND_COLOR,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayBackgroundColor"),
			"The background color of the decompiler window.");
		opt.registerOption(FONT_MSG, DEFAULT_FONT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayFont"),
			"The font used to render text in the decompiler.");
		opt.registerOption(SEARCH_HIGHLIGHT_MSG, SEARCH_HIGHLIGHT_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayFindHighlight"),
			"The color used to highlight matches using the Find Dialog.");
		opt.registerOption(LINE_NUMBER_MSG, LINE_NUMBER_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayLineNumbers"),
			"Toggle for displaying line numbers in the decompiler.");
		opt.registerOption(DECOMPILE_TIMEOUT, SUGGESTED_DECOMPILE_TIMEOUT_SECS,
			new HelpLocation(HelpTopics.DECOMPILER, "GeneralTimeout"),
			"The number of seconds to allow the decompiler to run before terminating the " +
				"decompiler.\nCurrently this does not affect the UI, which will run indefinitely. " +
				"This setting currently only affects background analysis that uses the decompiler.");
		opt.registerOption(PAYLOAD_LIMIT, SUGGESTED_MAX_PAYLOAD_BYTES,
			new HelpLocation(HelpTopics.DECOMPILER, "GeneralMaxPayload"),
			"The maximum size of the decompiler result payload in MBYtes (Suggested value: 50).");
		opt.registerOption(MAX_INSTRUCTIONS, SUGGESTED_MAX_INSTRUCTIONS,
			new HelpLocation(HelpTopics.DECOMPILER, "GeneralMaxInstruction"),
			"The maximum number of instructions decompiled in a single function");
		opt.registerOption(HIGHLIGHT_CURRENT_VARIABLE_MSG, HIGHLIGHT_CURRENT_VARIABLE_DEF,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayCurrentHighlight"),
			"Current variable highlight");
		opt.registerOption(CACHED_RESULTS_SIZE_MSG, SUGGESTED_CACHED_RESULTS_SIZE,
			new HelpLocation(HelpTopics.DECOMPILER, "GeneralCacheSize"), CACHE_RESULTS_DESCRIPTION);
		grabFromToolAndProgram(ownerPlugin, opt, program);
	}

	private static void appendOption(StringBuffer buf, String name, String p1, String p2,
			String p3) {
		buf.append(" <");
		buf.append(name);
		buf.append('>');
		if ((p2.length() == 0) && (p3.length() == 0)) {
			buf.append(p1);
		}
		else {
			buf.append('\n');
			buf.append("  <param1>");
			buf.append(p1);
			buf.append("</param1>\n");
			buf.append("  <param2>");
			buf.append(p2); // Print even if empty, as p3 isn't
			buf.append("</param2>\n");
			if (p3.length() != 0) {
				buf.append("  <param3>");
				buf.append(p3);
				buf.append("</param3>\n");
			}
		}
		buf.append("</");
		buf.append(name);
		buf.append(">\n");
	}

	/**
	 * Produce XML document of configuration options
	 * to be sent to decompiler process. This object
	 * is global to all decompile processes so we can
	 * tailor to the specific process by passing in the
	 * interface
	 * @param iface  specific DecompInterface being sent options
	 * @return XML document as a string
	 */
	public String getXML(DecompInterface iface) {
		StringBuffer buf = new StringBuffer();
		buf.append("<optionslist>\n");
		appendOption(buf, "currentaction", "conditionalexe", predicate ? "on" : "off", "");
		appendOption(buf, "readonly", readOnly ? "on" : "off", "", "");
		appendOption(buf, "currentaction", iface.getSimplificationStyle(), "unreachable",
			eliminateUnreachable ? "on" : "off");
		appendOption(buf, "currentaction", iface.getSimplificationStyle(), "doubleprecis",
			simplifyDoublePrecision ? "on" : "off");

		// Must set language early so that the object is in place before other option changes
		appendOption(buf, "setlanguage", displayLanguage.toString(), "", "");

		if (ignoreunimpl != IGNOREUNIMPL_OPTIONDEFAULT) {
			appendOption(buf, "ignoreunimplemented", ignoreunimpl ? "on" : "off", "", "");
		}
		if (inferconstptr != INFERCONSTPTR_OPTIONDEFAULT) {
			appendOption(buf, "inferconstptr", inferconstptr ? "on" : "off", "", "");
		}
		if (analyzeForLoops != ANALYZEFORLOOPS_OPTIONDEFAULT) {
			appendOption(buf, "analyzeforloops", analyzeForLoops ? "on" : "off", "", "");
		}
		if (nullToken != NULLTOKEN_OPTIONDEFAULT) {
			appendOption(buf, "nullprinting", nullToken ? "on" : "off", "", "");
		}
		if (inplaceTokens != INPLACEOP_OPTIONDEFAULT) {
			appendOption(buf, "inplaceops", inplaceTokens ? "on" : "off", "", "");
		}
		if (aliasBlock != ALIASBLOCK_OPTIONDEFAULT) {
			appendOption(buf, "aliasblock", aliasBlock.getOptionString(), "", "");
		}
		if (conventionPrint != CONVENTION_OPTIONDEFAULT) {
			appendOption(buf, "conventionprinting", conventionPrint ? "on" : "off", "", "");
		}
		if (noCastPrint != NOCAST_OPTIONDEFAULT) {
			appendOption(buf, "nocastprinting", noCastPrint ? "on" : "off", "", "");
		}
		if (maxwidth != MAXWIDTH_OPTIONDEFAULT) {
			appendOption(buf, "maxlinewidth", Integer.toString(maxwidth), "", "");
		}
		if (indentwidth != INDENTWIDTH_OPTIONDEFAULT) {
			appendOption(buf, "indentincrement", Integer.toString(indentwidth), "", "");
		}
		if (commentindent != COMMENTINDENT_OPTIONDEFAULT) {
			appendOption(buf, "commentindent", Integer.toString(commentindent), "", "");
		}
		if (commentStyle != COMMENTSTYLE_OPTIONDEFAULT) {
			String curstyle = CommentStyleEnum.CPPStyle.equals(commentStyle) ? "cplusplus" : "c";
			appendOption(buf, "commentstyle", curstyle, "", "");
		}
		if (commentPLATEInclude != COMMENTPLATE_OPTIONDEFAULT) {
			appendOption(buf, "commentinstruction", "header", commentPLATEInclude ? "on" : "off",
				"");
		}
		if (commentPREInclude != COMMENTPRE_OPTIONDEFAULT) {
			appendOption(buf, "commentinstruction", "user2", commentPREInclude ? "on" : "off", "");
		}
		if (commentEOLInclude != COMMENTEOL_OPTIONDEFAULT) {
			appendOption(buf, "commentinstruction", "user1", commentEOLInclude ? "on" : "off", "");
		}
		if (commentPOSTInclude != COMMENTPOST_OPTIONDEFAULT) {
			appendOption(buf, "commentinstruction", "user3", commentPOSTInclude ? "on" : "off", "");
		}
		if (commentWARNInclude != COMMENTWARN_OPTIONDEFAULT) {
			appendOption(buf, "commentinstruction", "warning", commentWARNInclude ? "on" : "off",
				"");
		}
		if (commentHeadInclude != COMMENTHEAD_OPTIONDEFAULT) {
			appendOption(buf, "commentheader", "header", commentHeadInclude ? "on" : "off", "");
		}
		if (commentWARNInclude != COMMENTWARN_OPTIONDEFAULT) {
			appendOption(buf, "commentheader", "warningheader", commentWARNInclude ? "on" : "off",
				"");
		}
		if (namespaceStrategy != NAMESPACE_OPTIONDEFAULT) {
			appendOption(buf, "namespacestrategy", namespaceStrategy.getOptionString(), "", "");
		}
		if (integerFormat != INTEGERFORMAT_OPTIONDEFAULT) {
			appendOption(buf, "integerformat", integerFormat.getOptionString(), "", "");
		}
		if (maxIntructionsPer != SUGGESTED_MAX_INSTRUCTIONS) {
			appendOption(buf, "maxinstruction", Integer.toString(maxIntructionsPer), "", "");
		}
		appendOption(buf, "protoeval", protoEvalModel, "", "");
		buf.append("</optionslist>\n");
		return buf.toString();
	}

	public int getMaxWidth() {
		return maxwidth;
	}

	public void setMaxWidth(int maxwidth) {
		this.maxwidth = maxwidth;
	}

	public Color getKeywordColor() {
		return keywordColor;
	}

	public Color getTypeColor() {
		return typeColor;
	}

	public Color getFunctionColor() {
		return functionColor;
	}

	public Color getCommentColor() {
		return commentColor;
	}

	public Color getConstantColor() {
		return constantColor;
	}

	public Color getVariableColor() {
		return variableColor;
	}

	public Color getParameterColor() {
		return parameterColor;
	}

	public Color getGlobalColor() {
		return globalColor;
	}

	public Color getDefaultColor() {
		return defaultColor;
	}

	public Color getCodeViewerBackgroundColor() {
		return codeViewerBackgroundColor;
	}

	public Color getCurrentVariableHighlightColor() {
		return currentVariableHighlightColor;
	}

	public Color getMiddleMouseHighlightColor() {
		return middleMouseHighlightColor;
	}

	public Color getSearchHighlightColor() {
		return defaultSearchHighlightColor;
	}

	public int getMiddleMouseHighlightButton() {
		return middleMouseHighlightButton;
	}

	public boolean isPRECommentIncluded() {
		return commentPREInclude;
	}

	public void setPRECommentIncluded(boolean commentPREInclude) {
		this.commentPREInclude = commentPREInclude;
	}

	public boolean isPLATECommentIncluded() {
		return commentPLATEInclude;
	}

	public void setPLATECommentIncluded(boolean commentPLATEInclude) {
		this.commentPLATEInclude = commentPLATEInclude;
	}

	public boolean isPOSTCommentIncluded() {
		return commentPOSTInclude;
	}

	public void setPOSTCommentIncluded(boolean commentPOSTInclude) {
		this.commentPOSTInclude = commentPOSTInclude;
	}

	public boolean isEOLCommentIncluded() {
		return commentEOLInclude;
	}

	public void setEOLCommentIncluded(boolean commentEOLInclude) {
		this.commentEOLInclude = commentEOLInclude;
	}

	public boolean isWARNCommentIncluded() {
		return commentWARNInclude;
	}

	public void setWARNCommentIncluded(boolean commentWARNInclude) {
		this.commentWARNInclude = commentWARNInclude;
	}

	public boolean isHeadCommentIncluded() {
		return commentHeadInclude;
	}

	public void setHeadCommentIncluded(boolean commentHeadInclude) {
		this.commentHeadInclude = commentHeadInclude;
	}

	public boolean isEliminateUnreachable() {
		return eliminateUnreachable;
	}

	public void setEliminateUnreachable(boolean eliminateUnreachable) {
		this.eliminateUnreachable = eliminateUnreachable;
	}

	public boolean isSimplifyDoublePrecision() {
		return simplifyDoublePrecision;
	}

	public void setSimplifyDoublePrecision(boolean simplifyDoublePrecision) {
		this.simplifyDoublePrecision = simplifyDoublePrecision;
	}

	public boolean isDisplayLineNumbers() {
		return displayLineNumbers;
	}

	public DecompilerLanguage getDisplayLanguage() {
		return displayLanguage;
	}

	public boolean isConventionPrint() {
		return conventionPrint;
	}

	public void setConventionPrint(boolean conventionPrint) {
		this.conventionPrint = conventionPrint;
	}

	public boolean isNoCastPrint() {
		return noCastPrint;
	}

	public void setNoCastPrint(boolean noCastPrint) {
		this.noCastPrint = noCastPrint;
	}

	public void setDisplayLanguage(DecompilerLanguage val) {
		displayLanguage = val;
	}

	public Font getDefaultFont() {
		return defaultFont;
	}

	public int getDefaultTimeout() {
		return decompileTimeoutSeconds;
	}

	public void setDefaultTimeout(int timeout) {
		decompileTimeoutSeconds = timeout;
	}

	public int getMaxPayloadMBytes() {
		return payloadLimitMBytes;
	}

	public void setMaxPayloadMBytes(int mbytes) {
		payloadLimitMBytes = mbytes;
	}

	public int getMaxInstructions() {
		return maxIntructionsPer;
	}

	public void setMaxInstructions(int num) {
		maxIntructionsPer = num;
	}

	public CommentStyleEnum getCommentStyle() {
		return commentStyle;
	}

	public void setCommentStyle(CommentStyleEnum commentStyle) {
		this.commentStyle = commentStyle;
	}

	public int getCacheSize() {
		return cachedResultsSize;
	}
}
