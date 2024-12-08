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
import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.awt.Color;
import java.awt.Font;
import java.awt.event.MouseEvent;
import java.io.IOException;

import generic.theme.GColor;
import generic.theme.Gui;
import ghidra.GhidraOptions;
import ghidra.GhidraOptions.CURSOR_MOUSE_BUTTON_NAMES;
import ghidra.app.util.HelpTopics;
import ghidra.app.util.template.TemplateSimplifier;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.ProgramCompilerSpec;
import ghidra.program.model.lang.*;
import ghidra.program.model.lang.CompilerSpec.EvaluationModelType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.ElementId;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.symbol.IdentityNameTransformer;
import ghidra.program.model.symbol.NameTransformer;
import ghidra.util.HelpLocation;

/**
 * Configuration options for the decompiler
 * This stores the options and can create an XML
 * string to be sent to the decompiler process
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
		"If set, branches and code that can never be executed are eliminated as dead code";
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

	private final static String SPLITSTRUCTURES_OPTIONSTRING =
		"Analysis.Split combined structure fields";
	private final static String SPLITSTRUCTURES_OPTIONDESCRIPTION =
		"If set, the decompiler will split a copy operation to or from a structure that affects more than " +
			"one field. The copy will be split into multiple operations so that each logical field is copied " +
			"separately.";
	private final static boolean SPLITSTRUCTURES_OPTIONDEFAULT = true;	// Must match Architecture::resetDefaultsInternal
	private boolean splitStructures;

	private final static String SPLITARRAYS_OPTIONSTRING = "Analysis.Split combined array elements";
	private final static String SPLITARRAYS_OPTIONDESCRIPTION =
		"If set, the decompiler will split a copy operation to or from an array that affects more than " +
			"one element. The copy will be split into multiple operations so that each logical element is copied " +
			"separately.";
	private final static boolean SPLITARRAYS_OPTIONDEFAULT = true;	// Must match Architecture::resetDefaultsInternal
	private boolean splitArrays;

	private final static String SPLITPOINTERS_OPTIONSTRING =
		"Analysis.Split pointers to combined elements";
	private final static String SPLITPOINTERS_OPTIONDESCRIPTION =
		"If set, a single copy, through a pointer, to either multiple array elements or multiple structure fields " +
			"will be split.  The copy, via LOAD or STORE, will be split into multiple operations so that each " +
			"logical element is accessed separately.";
	private final static boolean SPLITPOINTERS_OPTIONDEFAULT = true;	// Must match Architecture::resetDefaultsInternal
	private boolean splitPointers;

	private final static String NANIGNORE_OPTIONSTRING = "Analysis.NaN operations";
	private final static String NANIGNORE_OPTIONDESCRIPTION =
		"Specify how much to ignore floating-point NaN operations in decompiler output";

	public enum NanIgnoreEnum {

		None("none", "Ignore none"),
		Compare("compare", "Ignore with comparisons"),
		All("all", "Ignore all");

		private String label;
		private String optionString;

		private NanIgnoreEnum(String optString, String label) {
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

	private final static NanIgnoreEnum NANIGNORE_OPTIONDEFAULT = NanIgnoreEnum.Compare;	// Must match Architecture::resetDefaultsInternal
	private NanIgnoreEnum nanIgnore;

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
		"If set, the names of calling conventions (when they differ " +
			"from the default) will be printed as part of the function prototype.";
	private final static boolean CONVENTION_OPTIONDEFAULT = true;	// Must match PrintC::resetDefaultsPrintC
	private boolean conventionPrint;

	private final static String NOCAST_OPTIONSTRING = "Display.Disable printing of type casts";
	private final static String NOCAST_OPTIONDESCRIPTION =
		"If set, any C style type cast recovered by the decompiler will not be displayed. " +
			"The resulting C syntax may not parse correctly.";
	private final static boolean NOCAST_OPTIONDEFAULT = false;		// Must match PrintC::resetDefaultsPrintC
	private boolean noCastPrint;

	public enum BraceStyle {

		Same("same", "Same line"), Next("next", "Next line"), Skip("skip", "Skip one line");

		private String label;
		private String optionString;

		private BraceStyle(String optString, String label) {
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

	private final static String BRACEFUNCTION_OPTIONSTRING =
		"Display.Brace format for function blocks";
	private final static String BRACEFUNCTION_OPTIONDESCRIPTION =
		"Where the opening brace is displayed, after a function declaration";
	private final static BraceStyle BRACEFUNCTION_OPTIONDEFAULT = BraceStyle.Skip;
	private BraceStyle braceFunction;

	private final static String BRACEIFELSE_OPTIONSTRING =
		"Display.Brace format for if/else blocks";
	private final static String BRACEIFELSE_OPTIONDESCRIPTION =
		"Where the opening brace is displayed, for an if/else code block";
	private final static BraceStyle BRACEIFELSE_OPTIONDEFAULT = BraceStyle.Same;
	private BraceStyle braceIfElse;

	private final static String BRACELOOP_OPTIONSTRING = "Display.Brace format for loop blocks";
	private final static String BRACELOOP_OPTIONDESCRIPTION =
		"Where the opening brace is displayed, for the body of a loop";
	private final static BraceStyle BRACELOOP_OPTIONDEFAULT = BraceStyle.Same;
	private BraceStyle braceLoop;

	private final static String BRACESWITCH_OPTIONSTRING = "Display.Brace format for switch blocks";
	private final static String BRACESWITCH_OPTIONDESCRIPTION =
		"Where the opening brace is displayed, for the body of a switch statement";
	private final static BraceStyle BRACESWITCH_OPTIONDEFAULT = BraceStyle.Same;
	private BraceStyle braceSwitch;

	private final static String MAXWIDTH_OPTIONSTRING = "Display.Maximum characters in a code line";
	private final static String MAXWIDTH_OPTIONDESCRIPTION =
		"Maximum number of characters allowed per line before before line breaks are forced.";
	private final static int MAXWIDTH_OPTIONDEFAULT = 100;	// Must match EmitPrettyPrint::resetDefaultsPrettyPrint
	private int maxwidth;

	private final static String INDENTWIDTH_OPTIONSTRING =
		"Display.Number of characters per indent level";
	private final static String INDENTWIDTH_OPTIONDESCRIPTION =
		"Number of characters indented for each level of control-flow or scope nesting";
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
	public static final int SUGGESTED_MAX_JUMPTABLE_ENTRIES = 1024;		// Must match Architecture::resetDefaultsInternal

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
		"If set, disassembly plate comments are displayed in the decompiler C output";
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
		"If set, the entry point plate comment is displayed as a function header comment.";
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

	//@formatter:off
	private final static IntegerFormatEnum INTEGERFORMAT_OPTIONDEFAULT = IntegerFormatEnum.BestFit;		// Must match PrintLanguage::resetDefaultsInternal
	private IntegerFormatEnum integerFormat;

	private int middleMouseHighlightButton = MouseEvent.BUTTON2;

	private final static String HIGHLIGHT_CURRENT_VARIABLE_MSG ="Display.Color for Current Variable Highlight";
	private final static GColor HIGHLIGHT_CURRENT_VARIABLE_COLOR = new GColor("color.bg.decompiler.current.variable");

	private final static String HIGHLIGHT_KEYWORD_MSG = "Display.Color for Keywords";
	private final static GColor HIGHLIGHT_KEYWORD_COLOR = new GColor("color.fg.decompiler.keyword");

	private final static String HIGHLIGHT_FUNCTION_MSG = "Display.Color for Function names";
	private final static GColor HIGHLIGHT_FUNCTION_COLOR = new GColor("color.fg.decompiler.function.name");

	private final static String HIGHLIGHT_COMMENT_MSG = "Display.Color for Comments";
	private final static GColor HIGHLIGHT_COMMENT_COLOR = new GColor( "color.fg.decompiler.comment");

	private final static String HIGHLIGHT_VARIABLE_MSG = "Display.Color for Variables";
	private final static GColor HIGHLIGHT_VARIABLE_COLOR = new GColor("color.fg.decompiler.variable");

	private final static String HIGHLIGHT_CONST_MSG = "Display.Color for Constants";
	private final static GColor HIGHLIGHT_CONST_COLOR = new GColor("color.fg.decompiler.constant");

	private final static String HIGHLIGHT_TYPE_MSG = "Display.Color for Types";
	private final static GColor HIGHLIGHT_TYPE_COLOR = new GColor("color.fg.decompiler.type");

	private final static String HIGHLIGHT_PARAMETER_MSG = "Display.Color for Parameters";
	private final static GColor HIGHLIGHT_PARAMETER_COLOR = new GColor("color.fg.decompiler.parameter");

	private final static String HIGHLIGHT_GLOBAL_MSG = "Display.Color for Globals";
	private final static GColor HIGHLIGHT_GLOBAL_COLOR = new GColor("color.fg.decompiler.global");
	
	private final static String HIGHLIGHT_SPECIAL_MSG = "Display.Color for Special";
	private final static GColor HIGHLIGHT_SPECIAL_COLOR = new GColor("color.fg.decompiler.special");

	private final static String HIGHLIGHT_DEFAULT_MSG = "Display.Color Default";
	private final static GColor HIGHLIGHT_DEFAULT_COLOR =  new GColor("color.fg.decompiler");

	private static final String SEARCH_HIGHLIGHT_MSG = "Display.Color for Highlighting Find Matches";
	private static final GColor SEARCH_HIGHLIGHT_COLOR = new GColor("color.bg.decompiler.highlights.find");
	//@formatter:on

	private static final String BACKGROUND_COLOR_MSG = "Display.Background Color";
	private static final String BACKGROUND_COLOR_ID = "color.bg.decompiler";
	private static final GColor BACKGROUND_COLOR = new GColor(BACKGROUND_COLOR_ID);

	// Color applied to a token to indicate warning/error
	private final static Color ERROR_COLOR = new GColor("color.fg.decompiler.error");

	final static String FONT_MSG = "Display.Font";
	public final static String DEFAULT_FONT_ID = "font.decompiler";

	private final static String CACHED_RESULTS_SIZE_MSG = "Cache Size (Functions)";
	private final static int SUGGESTED_CACHED_RESULTS_SIZE = 10;
	private final static String CACHE_RESULTS_DESCRIPTION =
		"Number of Decompiled Functions to Cache in the Decompile Window";

	private final static String LINE_NUMBER_MSG = "Display.Display Line Numbers";
	private final static String DECOMPILE_TIMEOUT = "Decompiler Timeout (seconds)";
	private final static String PAYLOAD_LIMIT = "Decompiler Max-Payload (MBytes)";
	private final static String MAX_INSTRUCTIONS = "Max Instructions per Function";
	private final static String MAX_JUMPTABLE_ENTRIES = "Max Entries per Jumptable";
	private final static Boolean LINE_NUMBER_DEF = Boolean.TRUE;
	private boolean displayLineNumbers;
	private int decompileTimeoutSeconds;
	private int payloadLimitMBytes;
	private int maxIntructionsPer;
	private int maxJumpTableEntries;
	private int cachedResultsSize;

	private DecompilerLanguage displayLanguage; // Output language displayed by the decompiler

	private NameTransformer nameTransformer;	// Transformer applied to data-type/function names

	private String protoEvalModel; // Name of the prototype evaluation model

	public DecompileOptions() {
		predicate = PREDICATE_OPTIONDEFAULT;
		readOnly = READONLY_OPTIONDEFAULT; // This flipped values
		eliminateUnreachable = ELIMINATE_UNREACHABLE_OPTIONDEFAULT;
		simplifyDoublePrecision = SIMPLIFY_DOUBLEPRECISION_OPTIONDEFAULT;
		splitStructures = SPLITSTRUCTURES_OPTIONDEFAULT;
		splitArrays = SPLITARRAYS_OPTIONDEFAULT;
		splitPointers = SPLITPOINTERS_OPTIONDEFAULT;
		nanIgnore = NANIGNORE_OPTIONDEFAULT;
		ignoreunimpl = IGNOREUNIMPL_OPTIONDEFAULT;
		inferconstptr = INFERCONSTPTR_OPTIONDEFAULT;
		analyzeForLoops = ANALYZEFORLOOPS_OPTIONDEFAULT;
		nullToken = NULLTOKEN_OPTIONDEFAULT;
		inplaceTokens = INPLACEOP_OPTIONDEFAULT;
		aliasBlock = ALIASBLOCK_OPTIONDEFAULT;
		conventionPrint = CONVENTION_OPTIONDEFAULT;
		noCastPrint = NOCAST_OPTIONDEFAULT;
		braceFunction = BRACEFUNCTION_OPTIONDEFAULT;
		braceIfElse = BRACEIFELSE_OPTIONDEFAULT;
		braceLoop = BRACELOOP_OPTIONDEFAULT;
		braceSwitch = BRACESWITCH_OPTIONDEFAULT;
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
		displayLineNumbers = LINE_NUMBER_DEF;
		displayLanguage = ProgramCompilerSpec.DECOMPILER_OUTPUT_DEF;
		protoEvalModel = "default";
		decompileTimeoutSeconds = SUGGESTED_DECOMPILE_TIMEOUT_SECS;
		payloadLimitMBytes = SUGGESTED_MAX_PAYLOAD_BYTES;
		maxIntructionsPer = SUGGESTED_MAX_INSTRUCTIONS;
		maxJumpTableEntries = SUGGESTED_MAX_JUMPTABLE_ENTRIES;
		cachedResultsSize = SUGGESTED_CACHED_RESULTS_SIZE;
		nameTransformer = null;
	}

	/**
	 * Grab all the decompiler options from various sources within a specific tool and program
	 * and cache them in this object.
	 * @param fieldOptions the Options object containing options specific to listing fields
	 * @param opt          the Options object that contains the "tool options" specific to the decompiler
	 * @param program      the program whose "program options" are relevant to the decompiler
	 */
	public void grabFromToolAndProgram(ToolOptions fieldOptions, ToolOptions opt, Program program) {

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
		splitStructures =
			opt.getBoolean(SPLITSTRUCTURES_OPTIONSTRING, SPLITSTRUCTURES_OPTIONDEFAULT);
		splitArrays = opt.getBoolean(SPLITARRAYS_OPTIONSTRING, SPLITARRAYS_OPTIONDEFAULT);
		splitPointers = opt.getBoolean(SPLITPOINTERS_OPTIONSTRING, SPLITPOINTERS_OPTIONDEFAULT);
		nanIgnore = opt.getEnum(NANIGNORE_OPTIONSTRING, NANIGNORE_OPTIONDEFAULT);

		nullToken = opt.getBoolean(NULLTOKEN_OPTIONSTRING, NULLTOKEN_OPTIONDEFAULT);
		inplaceTokens = opt.getBoolean(INPLACEOP_OPTIONSTRING, INPLACEOP_OPTIONDEFAULT);
		aliasBlock = opt.getEnum(ALIASBLOCK_OPTIONSTRING, ALIASBLOCK_OPTIONDEFAULT);
		conventionPrint = opt.getBoolean(CONVENTION_OPTIONSTRING, CONVENTION_OPTIONDEFAULT);
		noCastPrint = opt.getBoolean(NOCAST_OPTIONSTRING, NOCAST_OPTIONDEFAULT);
		braceFunction = opt.getEnum(BRACEFUNCTION_OPTIONSTRING, BRACEFUNCTION_OPTIONDEFAULT);
		braceIfElse = opt.getEnum(BRACEIFELSE_OPTIONSTRING, BRACEIFELSE_OPTIONDEFAULT);
		braceLoop = opt.getEnum(BRACELOOP_OPTIONSTRING, BRACELOOP_OPTIONDEFAULT);
		braceSwitch = opt.getEnum(BRACESWITCH_OPTIONSTRING, BRACESWITCH_OPTIONDEFAULT);
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

		displayLineNumbers = opt.getBoolean(LINE_NUMBER_MSG, LINE_NUMBER_DEF);
		decompileTimeoutSeconds = opt.getInt(DECOMPILE_TIMEOUT, SUGGESTED_DECOMPILE_TIMEOUT_SECS);
		payloadLimitMBytes = opt.getInt(PAYLOAD_LIMIT, SUGGESTED_MAX_PAYLOAD_BYTES);
		maxIntructionsPer = opt.getInt(MAX_INSTRUCTIONS, SUGGESTED_MAX_INSTRUCTIONS);
		maxJumpTableEntries = opt.getInt(MAX_JUMPTABLE_ENTRIES, SUGGESTED_MAX_JUMPTABLE_ENTRIES);
		cachedResultsSize = opt.getInt(CACHED_RESULTS_SIZE_MSG, SUGGESTED_CACHED_RESULTS_SIZE);

		grabFromFieldOptions(fieldOptions);
	}

	private void grabFromFieldOptions(ToolOptions fieldOptions) {
		if (fieldOptions == null) {
			return;
		}

		CURSOR_MOUSE_BUTTON_NAMES mouseEvent =
			fieldOptions.getEnum(CURSOR_HIGHLIGHT_BUTTON_NAME, CURSOR_MOUSE_BUTTON_NAMES.MIDDLE);
		middleMouseHighlightButton = mouseEvent.getMouseEventID();
		nameTransformer = new TemplateSimplifier(fieldOptions);
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

	/**
	 * @return the default prototype to assume if no other information about a function is known
	 */
	public String getProtoEvalModel() {
		return protoEvalModel;
	}

	/**
	 * Set the default prototype model for the decompiler.  This is the model assumed if no other
	 * information about a function is known.
	 * @param protoEvalModel is the name of the prototype model to set as default
	 */
	public void setProtoEvalModel(String protoEvalModel) {
		this.protoEvalModel = protoEvalModel;
	}

	/**
	 * This registers all the decompiler tool options with ghidra, and has the side effect of
	 * pulling all the current values for the options if they exist
	 * @param fieldOptions the options object specific to listing fields
	 * @param opt          the options object specific to the decompiler
	 * @param program      the program
	 */
	public void registerOptions(ToolOptions fieldOptions, ToolOptions opt, Program program) {
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
		opt.registerOption(SPLITSTRUCTURES_OPTIONSTRING, SPLITSTRUCTURES_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisSplitStruct"),
			SPLITSTRUCTURES_OPTIONDESCRIPTION);
		opt.registerOption(SPLITARRAYS_OPTIONSTRING, SPLITARRAYS_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisSplitArray"),
			SPLITARRAYS_OPTIONDESCRIPTION);
		opt.registerOption(SPLITPOINTERS_OPTIONSTRING, SPLITPOINTERS_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisSplitPointers"),
			SPLITPOINTERS_OPTIONDESCRIPTION);
		opt.registerOption(NANIGNORE_OPTIONSTRING, NANIGNORE_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "AnalysisNanIgnore"),
			NANIGNORE_OPTIONDESCRIPTION);
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
		opt.registerOption(BRACEFUNCTION_OPTIONSTRING, BRACEFUNCTION_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayBraceFormatting"),
			BRACEFUNCTION_OPTIONDESCRIPTION);
		opt.registerOption(BRACEIFELSE_OPTIONSTRING, BRACEIFELSE_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayBraceFormatting"),
			BRACEIFELSE_OPTIONDESCRIPTION);
		opt.registerOption(BRACELOOP_OPTIONSTRING, BRACELOOP_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayBraceFormatting"),
			BRACELOOP_OPTIONDESCRIPTION);
		opt.registerOption(BRACESWITCH_OPTIONSTRING, BRACESWITCH_OPTIONDEFAULT,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayBraceFormatting"),
			BRACESWITCH_OPTIONDESCRIPTION);
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
		opt.registerThemeColorBinding(HIGHLIGHT_KEYWORD_MSG, HIGHLIGHT_KEYWORD_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting keywords.");
		opt.registerThemeColorBinding(HIGHLIGHT_TYPE_MSG, HIGHLIGHT_TYPE_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting types.");
		opt.registerThemeColorBinding(HIGHLIGHT_FUNCTION_MSG, HIGHLIGHT_FUNCTION_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting function names.");
		opt.registerThemeColorBinding(HIGHLIGHT_COMMENT_MSG, HIGHLIGHT_COMMENT_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting comments.");
		opt.registerThemeColorBinding(HIGHLIGHT_VARIABLE_MSG, HIGHLIGHT_VARIABLE_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting variables.");
		opt.registerThemeColorBinding(HIGHLIGHT_CONST_MSG, HIGHLIGHT_CONST_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting constants.");
		opt.registerThemeColorBinding(HIGHLIGHT_PARAMETER_MSG, HIGHLIGHT_PARAMETER_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting parameters.");
		opt.registerThemeColorBinding(HIGHLIGHT_GLOBAL_MSG, HIGHLIGHT_GLOBAL_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for highlighting global variables.");
		opt.registerThemeColorBinding(HIGHLIGHT_SPECIAL_MSG, HIGHLIGHT_SPECIAL_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayTokenColor"),
			"Color used for volatile or other exceptional variables.");
		opt.registerThemeColorBinding(HIGHLIGHT_DEFAULT_MSG, HIGHLIGHT_DEFAULT_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayColorDefault"),
			"The color used when a specific color is not specified.");
		opt.registerThemeColorBinding(BACKGROUND_COLOR_MSG, BACKGROUND_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayBackgroundColor"),
			"The background color of the decompiler window.");
		opt.registerThemeFontBinding(FONT_MSG, DEFAULT_FONT_ID,
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayFont"),
			"The font used to render text in the decompiler.");
		opt.registerThemeColorBinding(SEARCH_HIGHLIGHT_MSG, SEARCH_HIGHLIGHT_COLOR.getId(),
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
		opt.registerOption(MAX_JUMPTABLE_ENTRIES, SUGGESTED_MAX_JUMPTABLE_ENTRIES,
			new HelpLocation(HelpTopics.DECOMPILER, "GeneralMaxJumptable"),
			"The maximum number of entries that can be recovered from a single jumptable");
		opt.registerThemeColorBinding(HIGHLIGHT_CURRENT_VARIABLE_MSG,
			HIGHLIGHT_CURRENT_VARIABLE_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "DisplayCurrentHighlight"),
			"Current variable highlight");
		opt.registerOption(CACHED_RESULTS_SIZE_MSG, SUGGESTED_CACHED_RESULTS_SIZE,
			new HelpLocation(HelpTopics.DECOMPILER, "GeneralCacheSize"), CACHE_RESULTS_DESCRIPTION);
		grabFromToolAndProgram(fieldOptions, opt, program);
	}

	private static void appendOption(Encoder encoder, ElementId option, String p1, String p2,
			String p3) throws IOException {
		encoder.openElement(option);
		if ((p2.length() == 0) && (p3.length() == 0)) {
			encoder.writeString(ATTRIB_CONTENT, p1);
		}
		else {
			encoder.openElement(ELEM_PARAM1);
			encoder.writeString(ATTRIB_CONTENT, p1);
			encoder.closeElement(ELEM_PARAM1);
			encoder.openElement(ELEM_PARAM2);
			encoder.writeString(ATTRIB_CONTENT, p2);	// Print even if empty, as p3 isn't
			encoder.closeElement(ELEM_PARAM2);
			if (p3.length() != 0) {
				encoder.openElement(ELEM_PARAM3);
				encoder.writeString(ATTRIB_CONTENT, p3);
				encoder.closeElement(ELEM_PARAM3);
			}
		}
		encoder.closeElement(option);
	}

	/**
	 * Encode all the configuration options to a stream for the decompiler process.
	 * This object is global to all decompile processes so we can tailor to the specific process
	 * by passing in the interface.
	 * @param encoder is the stream encoder
	 * @param iface  specific DecompInterface being sent options
	 * @throws IOException for errors writing to the underlying stream
	 */
	public void encode(Encoder encoder, DecompInterface iface) throws IOException {
		encoder.openElement(ELEM_OPTIONSLIST);
		if (predicate != PREDICATE_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_CURRENTACTION, "conditionalexe", predicate ? "on" : "off",
				"");
		}
		if (eliminateUnreachable != ELIMINATE_UNREACHABLE_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_CURRENTACTION, iface.getSimplificationStyle(), "unreachable",
				eliminateUnreachable ? "on" : "off");
		}
		if (simplifyDoublePrecision != SIMPLIFY_DOUBLEPRECISION_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_CURRENTACTION, iface.getSimplificationStyle(),
				"doubleprecis", simplifyDoublePrecision ? "on" : "off");
		}
		if (splitStructures != SPLITSTRUCTURES_OPTIONDEFAULT ||
			splitArrays != SPLITARRAYS_OPTIONDEFAULT ||
			splitPointers != SPLITPOINTERS_OPTIONDEFAULT) {
			String p1 = splitStructures ? "struct" : "";
			String p2 = splitArrays ? "array" : "";
			String p3 = splitPointers ? "pointer" : "";
			appendOption(encoder, ELEM_SPLITDATATYPE, p1, p2, p3);
		}
		if (nanIgnore != NANIGNORE_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_NANIGNORE, nanIgnore.getOptionString(), "", "");
		}

		appendOption(encoder, ELEM_READONLY, readOnly ? "on" : "off", "", "");
		// Must set language early so that the object is in place before other option changes
		appendOption(encoder, ELEM_SETLANGUAGE, displayLanguage.toString(), "", "");

		if (ignoreunimpl != IGNOREUNIMPL_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_IGNOREUNIMPLEMENTED, ignoreunimpl ? "on" : "off", "", "");
		}
		if (inferconstptr != INFERCONSTPTR_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_INFERCONSTPTR, inferconstptr ? "on" : "off", "", "");
		}
		if (analyzeForLoops != ANALYZEFORLOOPS_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_ANALYZEFORLOOPS, analyzeForLoops ? "on" : "off", "", "");
		}
		if (nullToken != NULLTOKEN_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_NULLPRINTING, nullToken ? "on" : "off", "", "");
		}
		if (inplaceTokens != INPLACEOP_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_INPLACEOPS, inplaceTokens ? "on" : "off", "", "");
		}
		if (aliasBlock != ALIASBLOCK_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_ALIASBLOCK, aliasBlock.getOptionString(), "", "");
		}
		if (conventionPrint != CONVENTION_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_CONVENTIONPRINTING, conventionPrint ? "on" : "off", "", "");
		}
		if (noCastPrint != NOCAST_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_NOCASTPRINTING, noCastPrint ? "on" : "off", "", "");
		}
		if (braceFunction != BRACEFUNCTION_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_BRACEFORMAT, "function", braceFunction.getOptionString(),
				"");
		}
		if (braceIfElse != BRACEIFELSE_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_BRACEFORMAT, "ifelse", braceIfElse.getOptionString(), "");
		}
		if (braceLoop != BRACELOOP_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_BRACEFORMAT, "loop", braceLoop.getOptionString(), "");
		}
		if (braceSwitch != BRACESWITCH_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_BRACEFORMAT, "switch", braceSwitch.getOptionString(), "");
		}
		if (maxwidth != MAXWIDTH_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_MAXLINEWIDTH, Integer.toString(maxwidth), "", "");
		}
		if (indentwidth != INDENTWIDTH_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_INDENTINCREMENT, Integer.toString(indentwidth), "", "");
		}
		if (commentindent != COMMENTINDENT_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_COMMENTINDENT, Integer.toString(commentindent), "", "");
		}
		if (commentStyle != COMMENTSTYLE_OPTIONDEFAULT) {
			String curstyle = CommentStyleEnum.CPPStyle.equals(commentStyle) ? "cplusplus" : "c";
			appendOption(encoder, ELEM_COMMENTSTYLE, curstyle, "", "");
		}
		if (commentPLATEInclude != COMMENTPLATE_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_COMMENTINSTRUCTION, "header",
				commentPLATEInclude ? "on" : "off", "");
		}
		if (commentPREInclude != COMMENTPRE_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_COMMENTINSTRUCTION, "user2",
				commentPREInclude ? "on" : "off", "");
		}
		if (commentEOLInclude != COMMENTEOL_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_COMMENTINSTRUCTION, "user1",
				commentEOLInclude ? "on" : "off", "");
		}
		if (commentPOSTInclude != COMMENTPOST_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_COMMENTINSTRUCTION, "user3",
				commentPOSTInclude ? "on" : "off", "");
		}
		if (commentWARNInclude != COMMENTWARN_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_COMMENTINSTRUCTION, "warning",
				commentWARNInclude ? "on" : "off", "");
		}
		if (commentHeadInclude != COMMENTHEAD_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_COMMENTHEADER, "header", commentHeadInclude ? "on" : "off",
				"");
		}
		if (commentWARNInclude != COMMENTWARN_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_COMMENTHEADER, "warningheader",
				commentWARNInclude ? "on" : "off", "");
		}
		if (namespaceStrategy != NAMESPACE_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_NAMESPACESTRATEGY, namespaceStrategy.getOptionString(), "",
				"");
		}
		if (integerFormat != INTEGERFORMAT_OPTIONDEFAULT) {
			appendOption(encoder, ELEM_INTEGERFORMAT, integerFormat.getOptionString(), "", "");
		}
		if (maxIntructionsPer != SUGGESTED_MAX_INSTRUCTIONS) {
			appendOption(encoder, ELEM_MAXINSTRUCTION, Integer.toString(maxIntructionsPer), "", "");
		}
		if (maxJumpTableEntries != SUGGESTED_MAX_JUMPTABLE_ENTRIES) {
			appendOption(encoder, ELEM_JUMPTABLEMAX, Integer.toString(maxJumpTableEntries), "", "");
		}
		appendOption(encoder, ELEM_PROTOEVAL, protoEvalModel, "", "");
		encoder.closeElement(ELEM_OPTIONSLIST);
	}

	/**
	 * @return the brace formatting style for function bodies
	 */
	public BraceStyle getFunctionBraceFormat() {
		return braceFunction;
	}

	/**
	 * Set how braces are formatted around a function body
	 * @param style is the formatting style
	 */
	public void setFunctionBraceFormat(BraceStyle style) {
		this.braceFunction = style;
	}

	/**
	 * @return the brace formatting style for if/else code blocks
	 */
	public BraceStyle getIfElseBraceFormat() {
		return braceIfElse;
	}

	/**
	 * Set how braces are formatted around an if/else code block
	 * @param style is the formatting style
	 */
	public void setIfElseBraceFormat(BraceStyle style) {
		this.braceIfElse = style;
	}

	/**
	 * @return the brace formatting style for loop bodies
	 */
	public BraceStyle getLoopBraceFormat() {
		return braceLoop;
	}

	/**
	 * Set how braces are formatted a loop body
	 * @param style is the formatting style
	 */
	public void setLoopBraceFormat(BraceStyle style) {
		this.braceLoop = style;
	}

	/**
	 * @return the brace formatting style for switch blocks
	 */
	public BraceStyle getSwitchBraceFormat() {
		return braceSwitch;
	}

	/**
	 * Set how braces are formatted around a switch block
	 * @param style is the formatting style
	 */
	public void setSwitchBraceFormat(BraceStyle style) {
		this.braceSwitch = style;
	}

	/**
	 * @return the maximum number of characters the decompiler displays in a single line of output
	 */
	public int getMaxWidth() {
		return maxwidth;
	}

	/**
	 * Set the maximum number of characters the decompiler displays in a single line of output
	 * @param maxwidth is the maximum number of characters
	 */
	public void setMaxWidth(int maxwidth) {
		this.maxwidth = maxwidth;
	}

	/**
	 * @return color associated with keyword tokens
	 */
	public Color getKeywordColor() {
		return HIGHLIGHT_KEYWORD_COLOR;
	}

	/**
	 * @return color associated with data-type tokens
	 */
	public Color getTypeColor() {
		return HIGHLIGHT_TYPE_COLOR;
	}

	/**
	 * @return color associated with a function name token
	 */
	public Color getFunctionColor() {
		return HIGHLIGHT_FUNCTION_COLOR;
	}

	/**
	 * @return color used to display comments
	 */
	public Color getCommentColor() {
		return HIGHLIGHT_COMMENT_COLOR;
	}

	/**
	 * @return color associated with constant tokens
	 */
	public Color getConstantColor() {
		return HIGHLIGHT_CONST_COLOR;
	}

	/**
	 * @return color associated with (local) variable tokens
	 */
	public Color getVariableColor() {
		return HIGHLIGHT_VARIABLE_COLOR;
	}

	/**
	 * @return color associated with parameter tokens
	 */
	public Color getParameterColor() {
		return HIGHLIGHT_PARAMETER_COLOR;
	}

	/**
	 * @return color associated with global variable tokens
	 */
	public Color getGlobalColor() {
		return HIGHLIGHT_GLOBAL_COLOR;
	}

	/**
	 * @return color associated with volatile variables or other special tokens
	 */
	public Color getSpecialColor() {
		return HIGHLIGHT_SPECIAL_COLOR;
	}

	/**
	 * @return color for generic syntax or other unspecified tokens
	 */
	public Color getDefaultColor() {
		return HIGHLIGHT_DEFAULT_COLOR;
	}

	/**
	 * @return color used on tokens that need to warn of an error or other unusual conditions
	 */
	public Color getErrorColor() {
		return ERROR_COLOR;
	}

	/**
	 * @return the background color for the decompiler window
	 */
	public Color getBackgroundColor() {
		return BACKGROUND_COLOR;
	}

	/**
	 * @return the color used display the current highlighted variable
	 */
	public Color getCurrentVariableHighlightColor() {
		return HIGHLIGHT_CURRENT_VARIABLE_COLOR;
	}

	/**
	 * @return color used to highlight token(s) selected with a middle button clock
	 */
	public Color getMiddleMouseHighlightColor() {
		return GhidraOptions.DEFAULT_HIGHLIGHT_COLOR;
	}

	/**
	 * @return color used to highlight search results
	 */
	public Color getSearchHighlightColor() {
		return SEARCH_HIGHLIGHT_COLOR;
	}

	/**
	 * @return the mouse button that should be used to toggle the primary token highlight
	 */
	public int getMiddleMouseHighlightButton() {
		return middleMouseHighlightButton;
	}

	/**
	 * @return true if Pre comments are included as part of decompiler output
	 */
	public boolean isPRECommentIncluded() {
		return commentPREInclude;
	}

	/**
	 * Set whether Pre comments are displayed as part of decompiler output
	 * @param commentPREInclude is true if Pre comments are output
	 */
	public void setPRECommentIncluded(boolean commentPREInclude) {
		this.commentPREInclude = commentPREInclude;
	}

	/**
	 * @return true if Plate comments are included as part of decompiler output
	 */
	public boolean isPLATECommentIncluded() {
		return commentPLATEInclude;
	}

	/**
	 * Set whether Plate comments are displayed as part of decompiler output
	 * @param commentPLATEInclude is true if Plate comments are output
	 */
	public void setPLATECommentIncluded(boolean commentPLATEInclude) {
		this.commentPLATEInclude = commentPLATEInclude;
	}

	/**
	 * @return true if Post comments are included as part of decompiler output
	 */
	public boolean isPOSTCommentIncluded() {
		return commentPOSTInclude;
	}

	/**
	 * Set whether Post comments are displayed as part of decompiler output
	 * @param commentPOSTInclude is true if Post comments are output
	 */
	public void setPOSTCommentIncluded(boolean commentPOSTInclude) {
		this.commentPOSTInclude = commentPOSTInclude;
	}

	/**
	 * @return true if End-of-line comments are included as part of decompiler output
	 */
	public boolean isEOLCommentIncluded() {
		return commentEOLInclude;
	}

	/**
	 * Set whether End-of-line comments are displayed as part of decompiler output.
	 * @param commentEOLInclude is true if End-of-line comments are output
	 */
	public void setEOLCommentIncluded(boolean commentEOLInclude) {
		this.commentEOLInclude = commentEOLInclude;
	}

	/**
	 * @return true if WARNING comments are included as part of decompiler output
	 */
	public boolean isWARNCommentIncluded() {
		return commentWARNInclude;
	}

	/**
	 * Set whether automatically generated WARNING comments are displayed as part of
	 * decompiler output.
	 * @param commentWARNInclude is true if WARNING comments are output
	 */
	public void setWARNCommentIncluded(boolean commentWARNInclude) {
		this.commentWARNInclude = commentWARNInclude;
	}

	/**
	 * @return true if function header comments are included as part of decompiler output
	 */
	public boolean isHeadCommentIncluded() {
		return commentHeadInclude;
	}

	/**
	 * Set whether function header comments are included as part of decompiler output.
	 * @param commentHeadInclude is true if header comments are output
	 */
	public void setHeadCommentIncluded(boolean commentHeadInclude) {
		this.commentHeadInclude = commentHeadInclude;
	}

	/**
	 * @return true if the decompiler currently eliminates unreachable code
	 */
	public boolean isEliminateUnreachable() {
		return eliminateUnreachable;
	}

	/**
	 * Set whether the decompiler should eliminate unreachable code as part of its analysis.
	 * @param eliminateUnreachable is true if unreachable code is eliminated
	 */
	public void setEliminateUnreachable(boolean eliminateUnreachable) {
		this.eliminateUnreachable = eliminateUnreachable;
	}

	/**
	 * @return true if the decompiler currently respects read-only flags
	 */
	public boolean isRespectReadOnly() {
		return readOnly;
	}

	/**
	 * Set whether the decompiler should respect read-only flags as part of its analysis.
	 * @param readOnly is true if read-only flags are respected
	 */
	public void setRespectReadOnly(boolean readOnly) {
		this.readOnly = readOnly;
	}

	/**
	 * If the decompiler currently applies transformation rules that identify and
	 * simplify double precision arithmetic operations, true is returned.
	 * @return true if the decompiler applies double precision rules
	 */
	public boolean isSimplifyDoublePrecision() {
		return simplifyDoublePrecision;
	}

	/**
	 * Set whether the decompiler should apply transformation rules that identify and
	 * simplify double precision arithmetic operations.
	 * @param simplifyDoublePrecision is true if double precision rules should be applied
	 */
	public void setSimplifyDoublePrecision(boolean simplifyDoublePrecision) {
		this.simplifyDoublePrecision = simplifyDoublePrecision;
	}

	/**
	 * @return true if line numbers should be displayed with decompiler output.
	 */
	public boolean isDisplayLineNumbers() {
		return displayLineNumbers;
	}

	/**
	 * @return the source programming language that decompiler output is rendered in
	 */
	public DecompilerLanguage getDisplayLanguage() {
		return displayLanguage;
	}

	/**
	 * Retrieve the transformer being applied to data-type, function, and namespace names.
	 * If no transform is being applied, a pass-through object is returned.
	 * @return the transformer object
	 */
	public NameTransformer getNameTransformer() {
		if (nameTransformer == null) {
			nameTransformer = new IdentityNameTransformer();
		}
		return nameTransformer;
	}

	/**
	 * Set a specific transformer to be applied to all data-type, function, and namespace
	 * names in decompiler output.  A null value indicates no transform should be applied.
	 * @param transformer is the transformer to apply
	 */
	public void setNameTransformer(NameTransformer transformer) {
		nameTransformer = transformer;
	}

	/**
	 * @return true if calling convention names are displayed as part of function signatures
	 */
	public boolean isConventionPrint() {
		return conventionPrint;
	}

	/**
	 * Set whether the calling convention name should be displayed as part of function signatures
	 * in decompiler output.
	 * @param conventionPrint is true if calling convention names should be displayed
	 */
	public void setConventionPrint(boolean conventionPrint) {
		this.conventionPrint = conventionPrint;
	}

	/**
	 * @return true if cast operations are not displayed in decompiler output
	 */
	public boolean isNoCastPrint() {
		return noCastPrint;
	}

	/**
	 * Set whether decompiler output should display cast operations.
	 * @param noCastPrint is true if casts should NOT be displayed.
	 */
	public void setNoCastPrint(boolean noCastPrint) {
		this.noCastPrint = noCastPrint;
	}

	/**
	 * Set the source programming language that decompiler output should be rendered in.
	 * @param val is the source language
	 */
	public void setDisplayLanguage(DecompilerLanguage val) {
		displayLanguage = val;
	}

	/**
	 * @return the font that should be used to render decompiler output
	 */
	public Font getDefaultFont() {
		return Gui.getFont(DEFAULT_FONT_ID);
	}

	/**
	 * If the time a decompiler process is allowed to analyze a single
	 * function exceeds this value, decompilation is aborted.
	 * @return the maximum time in seconds
	 */
	public int getDefaultTimeout() {
		return decompileTimeoutSeconds;
	}

	/**
	 * Set the maximum time (in seconds) a decompiler process is allowed to analyze a single
	 * function. If it is exceeded, decompilation is aborted.
	 * @param timeout is the maximum time in seconds
	 */
	public void setDefaultTimeout(int timeout) {
		decompileTimeoutSeconds = timeout;
	}

	/**
	 * If the size (in megabytes) of the payload returned by the decompiler
	 * process exceeds this value for a single function, decompilation is
	 * aborted.
	 * @return the maximum number of megabytes in a function payload
	 */
	public int getMaxPayloadMBytes() {
		return payloadLimitMBytes;
	}

	/**
	 * Set the maximum size (in megabytes) of the payload that can be returned by the decompiler
	 * process when analyzing a single function.  If this size is exceeded, decompilation is
	 * aborted.
	 * @param mbytes is the maximum number of megabytes in a function payload
	 */
	public void setMaxPayloadMBytes(int mbytes) {
		payloadLimitMBytes = mbytes;
	}

	/**
	 * If the number of assembly instructions in a function exceeds this value, the function
	 * is not decompiled.
	 * @return the maximum number of instructions
	 */
	public int getMaxInstructions() {
		return maxIntructionsPer;
	}

	/**
	 * Set the maximum number of assembly instructions in a function to decompile.
	 * If the number exceeds this, the function is not decompiled.
	 * @param num is the number of instructions
	 */
	public void setMaxInstructions(int num) {
		maxIntructionsPer = num;
	}

	/**
	 * If the number of entries in a single jumptable exceeds this value, the decompiler will
	 * not recover the table and control flow from the indirect jump corresponding to the table
	 * will not be followed.
	 * @return the maximum number of entries
	 */
	public int getMaxJumpTableEntries() {
		return maxJumpTableEntries;
	}

	/**
	 * Set the maximum number of entries the decompiler will recover from a single jumptable.
	 * If the number exceeds this, the table is not recovered and control flow from the
	 * corresponding indirect jump is not followed.
	 * @param num is the number of entries
	 */
	public void setMaxJumpTableEntries(int num) {
		maxJumpTableEntries = num;
	}

	/**
	 * @return the style in which comments are printed in decompiler output
	 */
	public CommentStyleEnum getCommentStyle() {
		return commentStyle;
	}

	/**
	 * Set the style in which comments are printed as part of decompiler output
	 * @param commentStyle is the new style to set
	 */
	public void setCommentStyle(CommentStyleEnum commentStyle) {
		this.commentStyle = commentStyle;
	}

	/**
	 * Return the maximum number of decompiled function results that should be cached
	 * by the controller of the decompiler process.
	 * @return the number of functions to cache
	 */
	public int getCacheSize() {
		return cachedResultsSize;
	}

}
