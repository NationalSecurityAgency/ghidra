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
package ghidra.lisa.gui;

import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.lisa.pcode.analyses.*;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.bean.opteditor.OptionsVetoException;
import it.unive.lisa.DefaultConfiguration;
import it.unive.lisa.analysis.dataflow.*;
import it.unive.lisa.analysis.heap.*;
import it.unive.lisa.analysis.heap.pointbased.FieldSensitivePointBasedHeap;
import it.unive.lisa.analysis.heap.pointbased.PointBasedHeap;
import it.unive.lisa.analysis.nonInterference.NonInterference;
import it.unive.lisa.analysis.nonrelational.inference.InferenceSystem;
import it.unive.lisa.analysis.nonrelational.value.TypeEnvironment;
import it.unive.lisa.analysis.nonrelational.value.ValueEnvironment;
import it.unive.lisa.analysis.type.TypeDomain;
import it.unive.lisa.analysis.types.InferredTypes;
import it.unive.lisa.analysis.types.StaticTypes;
import it.unive.lisa.analysis.value.ValueDomain;
import it.unive.lisa.conf.LiSAConfiguration.DescendingPhaseType;
import it.unive.lisa.conf.LiSAConfiguration.GraphType;
import it.unive.lisa.interprocedural.*;
import it.unive.lisa.interprocedural.callgraph.*;
import it.unive.lisa.interprocedural.context.*;

/**
 * Parameters used to control LiSA
 */
public class LisaOptions implements OptionsChangeListener {

	// ResourceManager may be able to pull these from a configuration.

	public final static String OP_KEY_LISA_ANALYSIS_HEAP = "Domain.Heap";
	public final static String OP_KEY_LISA_ANALYSIS_TYPE = "Domain.Type";
	public final static String OP_KEY_LISA_ANALYSIS_VALUE = "Domain.Value";

	public final static String OP_KEY_LISA_ANALYSIS_CALL_GRAPH = "CallGraph";
	public final static String OP_KEY_LISA_ANALYSIS_DESC = "DescendingPhase";
	public final static String OP_KEY_LISA_ANALYSIS_INTER = "Interprocedural";
	public final static String OP_KEY_LISA_ANALYSIS_CALL = "OpenCallPolicy";
	public final static String OP_KEY_LISA_ANALYSIS_OPT = "OptimizeResults";
	public final static String OP_KEY_LISA_ANALYSIS_POST = "Post-State (vs Pre-)";
	public final static String OP_KEY_LISA_ANALYSIS_SHOW_TOP = "Display 'top' values";
	public final static String OP_KEY_LISA_ANALYSIS_SHOW_UNIQUE = "Display 'unique' values";
	public final static String OP_KEY_LISA_ANALYSIS_USE_HIGH_PCODE = "Use high pcode (experimental)";
	public final static String OP_KEY_LISA_ANALYSIS_SIMPLIFICATION_STYLE =
		"Decompiler simplification style";
	public final static String OP_KEY_LISA_ANALYSIS_CALL_DEPTH = "Compute CFGs to Depth";
	public final static String OP_KEY_LISA_ANALYSIS_THRESH = "Threshhold";

	public final static String OP_KEY_LISA_ANALYSIS_GRAPH = "Output.GraphFormat";
	public final static String OP_KEY_LISA_ANALYSIS_OUTDIR = "Output.WorkDir";
	public final static String OP_KEY_LISA_ANALYSIS_SERIAL = "Output.SerializeResults";

	public final static String DEFAULT_LISA_ANALYSIS_HEAP = HeapDomainOption.DEFAULT.optionString;
	public final static String DEFAULT_LISA_ANALYSIS_TYPE = TypeDomainOption.DEFAULT.optionString;
	public final static String DEFAULT_LISA_ANALYSIS_VALUE = ValueDomainOption.DEFAULT.optionString;

	public final static String DEFAULT_LISA_ANALYSIS_CALL_GRAPH =
		CallGraphOption.RTA.optionString;
	public final static String DEFAULT_LISA_ANALYSIS_DESC =
		InterproceduralOption.DEFAULT.optionString;
	public final static String DEFAULT_LISA_ANALYSIS_INTER =
		InterproceduralOption.DEFAULT.optionString;
	public final static String DEFAULT_LISA_ANALYSIS_CALL = CallOption.DEFAULT.optionString;
	public final static boolean DEFAULT_LISA_ANALYSIS_OPT = false;
	public final static boolean DEFAULT_LISA_ANALYSIS_POST = false;
	public final static boolean DEFAULT_LISA_ANALYSIS_SHOW_TOP = false;
	public final static boolean DEFAULT_LISA_ANALYSIS_SHOW_UNIQUE = false;
	public final static boolean DEFAULT_LISA_ANALYSIS_USE_HIGH_PCODE = false;
	public final static String DEFAULT_LISA_ANALYSIS_SIMPLIFICATION_STYLE = "normalize";
	public final static int    DEFAULT_LISA_ANALYSIS_CALL_DEPTH = 0;
	public final static int    DEFAULT_LISA_ANALYSIS_THRESH = 5;
	
	public final static String DEFAULT_LISA_ANALYSIS_OUTDIR = "";
	public final static String DEFAULT_LISA_ANALYSIS_GRAPH = GraphOption.DEFAULT.optionString;
	public final static boolean DEFAULT_LISA_ANALYSIS_SERIAL = false;

	public final static String DEFAULT_LISA_TOP_REPRESENTATION = "#TOP#";
	private static String suppress;  // Suppressed in results (typically #TOP#)

	private LisaPlugin plugin;

	private HeapDomainOption heapDomainOption;
	private TypeDomainOption typeDomainOption;
	private ValueDomainOption valueDomainOption;
	private InterproceduralOption interproceduralOption;
	private DescendingPhaseOption descendingPhaseOption;
	private CallOption callOption;
	private GraphOption graphOption;
	private CallGraphOption callGraphOption;
	private int cfgDepth;
	private static int threshhold;
	private String outputDir;
	private boolean serialize;
	private boolean optimize;
	private boolean postState;
	private boolean showTop;
	private boolean showUnique;
	private boolean useHighPcode;
	private String simplificationStyle;

	public LisaOptions(LisaPlugin lisaPlugin) {
		this.plugin = lisaPlugin;
	}

	public static enum HeapDomainOption {
		HEAP_MONOLITHIC("Monolithic"),
		HEAP_POINTBASED("PointBased"),
		HEAP_FIELDSENSITIVE("FieldSensitivePointBased"),
		HEAP_TYPEBASED("TypeBased"),
		DEFAULT("DEFAULT(Monolithic)");

		private String optionString;

		private HeapDomainOption(String optString) {
			this.optionString = optString;
		}

		@Override
		public String toString() {
			return optionString;
		}

		@SuppressWarnings("rawtypes")
		public HeapDomain getDomain() {
			return switch (this) {
				case HEAP_MONOLITHIC -> new MonolithicHeap();
				case HEAP_POINTBASED -> new PointBasedHeap();
				case HEAP_FIELDSENSITIVE -> new FieldSensitivePointBasedHeap();
				case HEAP_TYPEBASED -> new TypeBasedHeap();
				default -> DefaultConfiguration.defaultHeapDomain();
			};
		}
	}

	public static enum TypeDomainOption {
		TYPE_INFERRED("Inferred"),
		TYPE_STATIC("Static"),
		DEFAULT("DEFAULT(Inferred)");

		private String optionString;

		private TypeDomainOption(String optString) {
			this.optionString = optString;
		}

		@Override
		public String toString() {
			return optionString;
		}

		@SuppressWarnings("rawtypes")
		public TypeDomain getDomain() {
			return switch (this) {
				case TYPE_INFERRED -> new TypeEnvironment<>(new InferredTypes());
				case TYPE_STATIC -> new TypeEnvironment<>(new StaticTypes());
				default -> DefaultConfiguration.defaultTypeDomain();
			};
		}
	}

	public static enum ValueDomainOption {
		VALUE_CONSTPROP("Numeric: ConstantPropagation"),
		VALUE_INTERVAL("Numeric: Interval"),
		VALUE_INTERVAL_LX86("Numeric: Interval (Low X86)"),
		VALUE_POWERSET("Numeric: NonRedundantPowersetOfInterval"),
		VALUE_PARITY("Numeric: Parity"),
		VALUE_PENTAGON("Numeric: Pentagon"),
		VALUE_PENTAGON_LX86("Numeric: Pentagon (Low X86)"),
		VALUE_SIGN("Numeric: Sign"),
		VALUE_UPPERBOUND("Numeric: UpperBound"),
		DDATA_AVAILABLE("Dataflow: AvailableExpressions"),
		DDATA_CONSTPROP("Dataflow: ConstantPropagation"),
		PDATA_REACHING("Dataflow: ReachingDefinitions"),
		PDATA_LIVENESS("Dataflow: Liveness"),
		VALUE_TAINT("Dataflow: Taint"),
		VALUE_TAINT3L("Dataflow: ThreeLevelTaint"),
		NONINTERFERENCE("NonInterference"),
		STABILITY("Stability"),
//		VALUE_TREND("Trend"),
//		VALUE_WHOLE("WholeValueAnalysis"),
		DEFAULT("DEFAULT(Interval)");

		private String optionString;

		private ValueDomainOption(String optString) {
			this.optionString = optString;
		}

		@Override
		public String toString() {
			return optionString;
		}

		@SuppressWarnings({ "rawtypes", "unchecked" })
		public ValueDomain getDomain(Program program) {
			suppress = DEFAULT_LISA_TOP_REPRESENTATION;
			if (this == VALUE_INTERVAL ||
				this == VALUE_INTERVAL_LX86 ||
				this == VALUE_PENTAGON ||
				this == VALUE_PENTAGON_LX86 ||
				this == VALUE_POWERSET) {
				suppress = "[-Inf, +Inf]";
			}
			if (this == VALUE_UPPERBOUND) {
				suppress = "{}";
			}
			if (this == STABILITY) {
				suppress = "=";
			}
			if (this == NONINTERFERENCE) {
				suppress = "HL";
			}
			if (this == VALUE_TAINT || this == VALUE_TAINT3L) {
				suppress = "_";
			}
			return switch (this) {
				case VALUE_CONSTPROP -> new ValueEnvironment<>(
					new PcodeByteBasedConstantPropagation(program.getLanguage()));
				case VALUE_INTERVAL -> new ValueEnvironment<>(new PcodeInterval());
				case VALUE_INTERVAL_LX86 -> new ValueEnvironment<>(new PcodeIntervalLowX86());
				case VALUE_PARITY -> new ValueEnvironment<>(new PcodeParity());
				case VALUE_PENTAGON -> new PcodePentagon();
				case VALUE_PENTAGON_LX86 -> new PcodePentagonLowX86();
				case VALUE_POWERSET -> new ValueEnvironment<>(
					new PcodeNonRedundantPowersetOfInterval());
				case VALUE_SIGN -> new ValueEnvironment<>(new PcodeSign());
				case VALUE_TAINT -> new ValueEnvironment<>(new PcodeTaint(false));
				case VALUE_TAINT3L -> new ValueEnvironment<>(new PcodeThreeLevelTaint());
				//case VALUE_TREND -> new ValueEnvironment<>(Trend.TOP);
				case VALUE_UPPERBOUND -> new ValueEnvironment<>(new PcodeUpperBounds());
				case DDATA_AVAILABLE -> new DefiniteDataflowDomain<>(new AvailableExpressions());
				case DDATA_CONSTPROP -> new DefiniteDataflowDomain<>(
					new PcodeDataflowConstantPropagation(program.getLanguage()));
				case PDATA_REACHING -> new PossibleDataflowDomain<>(new ReachingDefinitions());
				case PDATA_LIVENESS -> new PossibleDataflowDomain<>(new Liveness());
				case NONINTERFERENCE -> new InferenceSystem<>(new NonInterference());
				case STABILITY -> new PcodeStability(
					new ValueEnvironment<>(new PcodeInterval()).top());
				default -> new ValueEnvironment<>(new PcodeInterval());
			};
		}
	}

	public static enum InterproceduralOption {
		CONTEXT("ContextBased"),
		FULLSTACK("ContextBased(FullStackToken)"),
		KDEPTH("ContextBased(KDepthToken)"),
		LASTCALL("ContextBased(LastCallToken)"),
		INSENSITIVE("ContextBased(ContextInsensitiveToken)"),
		BACKWARDS("BackwardModularWorstCaseAnalysis"),
		DEFAULT("ModularWorstCaseAnalysis");

		private String optionString;

		private InterproceduralOption(String optString) {
			this.optionString = optString;
		}

		@Override
		public String toString() {
			return optionString;
		}

		@SuppressWarnings("rawtypes")
		public InterproceduralAnalysis<?> getAnalysis() {
			return switch (this) {
				case CONTEXT -> new ContextBasedAnalysis<>();
				case FULLSTACK -> new ContextBasedAnalysis<>(FullStackToken.getSingleton());
				case KDEPTH -> new ContextBasedAnalysis<>(KDepthToken.getSingleton(threshhold));
				case LASTCALL -> new ContextBasedAnalysis<>(LastCallToken.getSingleton());
				case INSENSITIVE -> new ContextBasedAnalysis<>(
					ContextInsensitiveToken.getSingleton());
				case BACKWARDS -> new BackwardModularWorstCaseAnalysis();
				default -> new ModularWorstCaseAnalysis<>();
			};
		}
	}

	public static enum DescendingPhaseOption {
		NARROWING("Narrowing"),
		GLB("GLB k-times"),
		DEFAULT("None");

		private String optionString;

		private DescendingPhaseOption(String optString) {
			this.optionString = optString;
		}

		@Override
		public String toString() {
			return optionString;
		}

		public DescendingPhaseType getType() {
			return switch (this) {
				case NARROWING -> DescendingPhaseType.NARROWING;
				case GLB -> DescendingPhaseType.GLB;
				default -> DescendingPhaseType.NONE;
			};
		}
	}

	public static enum CallOption {
		RETURNTOP("ReturnTop"),
		DEFAULT("WorstCase");

		private String optionString;

		private CallOption(String optString) {
			this.optionString = optString;
		}

		@Override
		public String toString() {
			return optionString;
		}

		public OpenCallPolicy getPolicy() {
			return switch (this) {
				case RETURNTOP -> ReturnTopPolicy.INSTANCE;
				default -> WorstCasePolicy.INSTANCE;
			};
		}
	}

	public static enum GraphOption {
		HTML("HTML"),
		HTMLSUB("HTML w/ subnodes"),
		DOT("Dot"),
		GRAPHML("GraphML"),
		GRAPHMLSUB("GraphML w/ subnodes"),
		DEFAULT("None");

		private String optionString;

		private GraphOption(String optString) {
			this.optionString = optString;
		}

		@Override
		public String toString() {
			return optionString;
		}

		public GraphType getType() {
			return switch (this) {
				case HTML -> GraphType.HTML;
				case HTMLSUB -> GraphType.HTML_WITH_SUBNODES;
				case DOT -> GraphType.DOT;
				case GRAPHML -> GraphType.GRAPHML;
				case GRAPHMLSUB -> GraphType.GRAPHML_WITH_SUBNODES;
				default -> GraphType.NONE;
			};
		}
	}

	public static enum CallGraphOption {
		CHA("Call Hierarchy Analysis"),
		RTA("Rapid Type Analysis");

		private String optionString;

		private CallGraphOption(String optString) {
			this.optionString = optString;
		}

		@Override
		public String toString() {
			return optionString;
		}

		public CallGraph getCallGraph() {
			return switch (this) {
				case CHA -> new CHACallGraph();
				default -> new RTACallGraph();
			};
		}
	}

	public static String makeDBName(String base, String binary_name) {
		StringBuilder sb = new StringBuilder();
		String[] parts = base.split("\\.");
		for (int i = 0; i < parts.length; ++i) {
			if (i > 0) {
				sb.append(".");
			}

			if (i == 2) {
				sb.append(binary_name);
				sb.append(".");
			}

			sb.append(parts[i]);
		}

		return sb.toString();
	}

	/**
	 * This registers all the decompiler tool options with ghidra, and has the side
	 * effect of pulling all the current values for the options if they exist
	 * 
	 * @param ownerPlugin the plugin to which the options should be registered
	 * @param opt         the options object to register with
	 * @param program     the program
	 */
	public void registerOptions(Plugin ownerPlugin, ToolOptions opt, Program program) {

		opt.registerOption(OP_KEY_LISA_ANALYSIS_HEAP, HeapDomainOption.DEFAULT,
			new HelpLocation(ownerPlugin.getName(), "domain_heap"),
			"Domain for the heap");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_TYPE, TypeDomainOption.DEFAULT,
			new HelpLocation(ownerPlugin.getName(), "domain_type"),
			"Domain for types");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_VALUE, ValueDomainOption.DEFAULT,
			new HelpLocation(ownerPlugin.getName(), "domain_value"),
			"Domain for values");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_INTER, InterproceduralOption.DEFAULT,
			new HelpLocation(ownerPlugin.getName(), "interprocedural"),
			"Interprocedural analysis");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_DESC, DescendingPhaseOption.DEFAULT,
			new HelpLocation(ownerPlugin.getName(), "descending_phase"),
			"Descending phase");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_CALL, CallOption.DEFAULT,
			new HelpLocation(ownerPlugin.getName(), "open_call_policy"),
			"Open call policy");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_POST, DEFAULT_LISA_ANALYSIS_POST,
			new HelpLocation(ownerPlugin.getName(), "post_state"),
			"Evaluate state post- or pre-statement");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_CALL_DEPTH, DEFAULT_LISA_ANALYSIS_CALL_DEPTH,
			new HelpLocation(ownerPlugin.getName(), "call_depth"),
			"Depth for CFG computation");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_THRESH, DEFAULT_LISA_ANALYSIS_THRESH,
			new HelpLocation(ownerPlugin.getName(), "threshhold"),
			"Threshhold (GLB or k-depth)");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_OUTDIR, DEFAULT_LISA_ANALYSIS_OUTDIR,
			new HelpLocation(ownerPlugin.getName(), "work_dir"),
			"Output directory");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_SERIAL, DEFAULT_LISA_ANALYSIS_SERIAL,
			new HelpLocation(ownerPlugin.getName(), "serialize"),
			"Serialize results");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_OPT, DEFAULT_LISA_ANALYSIS_OPT,
			new HelpLocation(ownerPlugin.getName(), "optimize"),
			"Optimize results");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_GRAPH, GraphOption.DEFAULT,
			new HelpLocation(ownerPlugin.getName(), "graph_format"),
			"Graph type");

		opt.registerOption(OP_KEY_LISA_ANALYSIS_CALL_GRAPH, CallGraphOption.RTA,
			new HelpLocation(ownerPlugin.getName(), "call_graph"),
			"Call graph input");

		grabFromToolAndProgram(ownerPlugin, opt, program);
		opt.addOptionsChangeListener(this);
	}

	/**
	 * Grab all the decompiler options from various sources within a specific tool
	 * and program and cache them in this object.
	 * 
	 * <p>
	 * NOTE: Overrides the defaults.
	 * 
	 * @param ownerPlugin the plugin that owns the "tool options" for the decompiler
	 * @param opt         the Options object that contains the "tool options"
	 *                    specific to the decompiler
	 * @param program     the program whose "program options" are relevant to the
	 *                    decompiler
	 */
	public void grabFromToolAndProgram(Plugin ownerPlugin, ToolOptions opt, Program program) {

		heapDomainOption = opt.getEnum(OP_KEY_LISA_ANALYSIS_HEAP, HeapDomainOption.DEFAULT);
		typeDomainOption = opt.getEnum(OP_KEY_LISA_ANALYSIS_TYPE, TypeDomainOption.DEFAULT);
		valueDomainOption = opt.getEnum(OP_KEY_LISA_ANALYSIS_VALUE, ValueDomainOption.DEFAULT);
		interproceduralOption =
			opt.getEnum(OP_KEY_LISA_ANALYSIS_INTER, InterproceduralOption.DEFAULT);
		descendingPhaseOption =
			opt.getEnum(OP_KEY_LISA_ANALYSIS_DESC, DescendingPhaseOption.DEFAULT);
		callOption = opt.getEnum(OP_KEY_LISA_ANALYSIS_CALL, CallOption.DEFAULT);
		graphOption = opt.getEnum(OP_KEY_LISA_ANALYSIS_GRAPH, GraphOption.DEFAULT);
		callGraphOption = opt.getEnum(OP_KEY_LISA_ANALYSIS_CALL_GRAPH, CallGraphOption.RTA);
		postState = opt.getBoolean(OP_KEY_LISA_ANALYSIS_POST, DEFAULT_LISA_ANALYSIS_POST);
		showTop = opt.getBoolean(OP_KEY_LISA_ANALYSIS_SHOW_TOP, DEFAULT_LISA_ANALYSIS_SHOW_TOP);
		showUnique = opt.getBoolean(OP_KEY_LISA_ANALYSIS_SHOW_UNIQUE, DEFAULT_LISA_ANALYSIS_SHOW_UNIQUE);
		useHighPcode = opt.getBoolean(OP_KEY_LISA_ANALYSIS_USE_HIGH_PCODE, DEFAULT_LISA_ANALYSIS_USE_HIGH_PCODE);
		simplificationStyle = opt.getString(OP_KEY_LISA_ANALYSIS_SIMPLIFICATION_STYLE,
			DEFAULT_LISA_ANALYSIS_SIMPLIFICATION_STYLE);
		cfgDepth = opt.getInt(OP_KEY_LISA_ANALYSIS_CALL_DEPTH, DEFAULT_LISA_ANALYSIS_CALL_DEPTH);
		threshhold = opt.getInt(OP_KEY_LISA_ANALYSIS_THRESH, DEFAULT_LISA_ANALYSIS_THRESH);
		outputDir = opt.getString(OP_KEY_LISA_ANALYSIS_OUTDIR, DEFAULT_LISA_ANALYSIS_OUTDIR);
		serialize = opt.getBoolean(OP_KEY_LISA_ANALYSIS_SERIAL, DEFAULT_LISA_ANALYSIS_SERIAL);
		optimize = opt.getBoolean(OP_KEY_LISA_ANALYSIS_OPT, DEFAULT_LISA_ANALYSIS_OPT);

	}

	public HeapDomainOption getHeapOption() {
		return heapDomainOption;
	}

	public void setHeapDomain(HeapDomainOption option) {
		this.heapDomainOption = option;
	}

	public TypeDomainOption getTypeOption() {
		return typeDomainOption;
	}

	public void setTypeDomain(TypeDomainOption option) {
		this.typeDomainOption = option;
	}

	public ValueDomainOption getValueOption() {
		return valueDomainOption;
	}

	public void setValueDomain(ValueDomainOption option) {
		this.valueDomainOption = option;
	}

	public InterproceduralOption getInterproceduralOption() {
		return interproceduralOption;
	}

	public void setInterproceduralOption(InterproceduralOption option) {
		this.interproceduralOption = option;
	}

	public DescendingPhaseOption getDescendingPhaseOption() {
		return descendingPhaseOption;
	}

	public void setDescendingPhaseOption(DescendingPhaseOption option) {
		this.descendingPhaseOption = option;
	}

	public CallOption getCallOption() {
		return callOption;
	}

	public void setCallOption(CallOption option) {
		this.callOption = option;
	}

	public int getCfgDepth() {
		return cfgDepth;
	}

	public void setCfgDepth(int cfgDepth) {
		this.cfgDepth = cfgDepth;
	}

	public int getThreshhold() {
		return threshhold;
	}

	public void setThreshhold(int threshhold) {
		LisaOptions.threshhold = threshhold;
	}

	public String getOutputDir() {
		return outputDir;
	}

	public void setOutputDir(String outputDir) {
		this.outputDir = outputDir;
	}

	public boolean isSerialize() {
		return serialize;
	}

	public void setSerialize(boolean serialize) {
		this.serialize = serialize;
	}

	public boolean isOptimize() {
		return optimize;
	}

	public void setOptimize(boolean optimize) {
		this.optimize = optimize;
	}

	public boolean isPostState() {
		return postState;
	}

	public void setPostState(boolean postState) {
		this.postState = postState;
	}

	public boolean isShowTop() {
		return showTop;
	}

	public void setShowTop(boolean showTop) {
		this.showTop = showTop;
	}

	public boolean isShowUnique() {
		return showUnique;
	}

	public void setShowUnique(boolean showUnique) {
		this.showUnique = showUnique;
	}

	public boolean isHighPcode() {
		return useHighPcode;
	}

	public void setHighPcode(boolean useHighPcode) {
		this.useHighPcode = useHighPcode;
	}

	public String getSimplificationStyle() {
		return simplificationStyle;
	}

	public void setSimplificationStyle(String style) {
		this.simplificationStyle = style;
	}

	public GraphOption getGraphOption() {
		return graphOption;
	}

	public void setGraphOption(GraphOption graphOption) {
		this.graphOption = graphOption;
	}

	public CallGraphOption getCallGraphOption() {
		return callGraphOption;
	}

	public void setCallGraphOption(CallGraphOption callGraphOption) {
		this.callGraphOption = callGraphOption;
	}

	public static String getTopValue() {
		return suppress;
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {
		if (optionName.equals(OP_KEY_LISA_ANALYSIS_USE_HIGH_PCODE)) {
			plugin.clearCfgs(null);
		}	
	}

}
