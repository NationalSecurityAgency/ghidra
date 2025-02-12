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
package ghidra.app.plugin.core.decompiler.taint;

import java.awt.Color;

import generic.theme.GColor;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin.*;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Taint information is used in the Decompiler Window.
 */
public class TaintOptions {

	// ResourceManager may be able to pull these from a configuration.

	// Option key strings for various directory and file paths.
	/* full path to where the GhidraScript puts the facts. */
	public final static String OP_KEY_TAINT_FACTS_DIR = "Taint.Directories.Facts";
	/* full path to where all query databases and other output lives -- not engine; not facts. */
	public final static String OP_KEY_TAINT_OUTPUT_DIR = "Taint.Directories.Output";
	/* full path to where the engine executable lives. */
	public final static String OP_KEY_TAINT_ENGINE_PATH = "Taint.Directories.Engine";

	/* The default name of the text file containing the query. */
	public final static String OP_KEY_TAINT_QUERY = "Taint.Query.Current Query";
	/* The default name of the index database file. */
	public final static String OP_KEY_TAINT_DB = "Taint.Query.Index";

	public final static String OP_KEY_TAINT_QUERY_ENGINE = "Taint.Query Engine";
	public final static String OP_KEY_TAINT_QUERY_DIRECTION = "Taint.Force Direction";
	public final static String OP_KEY_TAINT_QUERY_OUTPUT_FORM = "Taint.Output Format";
	/* Color used in the decompiler to highlight taint. */
	public final static String TAINT_HIGHLIGHT = "Taint.Highlight Color";
	/* How to apply highlight taint. */
	public final static String TAINT_HIGHLIGHT_STYLE = "Taint.Highlight Style";
	public final static String TAINT_ALL_ACCESS = "Taint.Match on Fields";
	private final static Boolean TAINT_ALL_ACCESS_PATHS = true;

	public final static String DEFAULT_TAINT_ENGINE_PATH = "";
	public final static String DEFAULT_TAINT_FACTS_DIR = "";
	public final static String DEFAULT_TAINT_OUTPUT_DIR = "";

	/* this is the text code that contains the datalog query the plugin writes. */
	public final static String DEFAULT_TAINT_QUERY = "taintquery.dl";
	public final static String DEFAULT_TAINT_DB = "ctadlir.db";

	public final static Boolean DEFAULT_GET_PATHS = true;

	private final static GColor TAINT_HIGHLIGHT_COLOR =
		new GColor("color.bg.listing.highlighter.default");
	private final static Highlighter TAINT_HIGHLIGHT_STYLE_DEFAULT = Highlighter.DEFAULT;

	private String taintEnginePath;
	private String taintFactsDir;
	private String taintOutputDir;

	private String taintQuery;
	private String taintDB;

	private String taintQueryEngine;
	private TaintDirection taintQueryDirection;
	private TaintFormat taintQueryOutputForm;

	private Highlighter taintHighlightStyle;
	private Color taintHighlightColor;
	private Boolean taintUseAllAccess;

	private TaintProvider taintProvider;

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

	public TaintOptions(TaintProvider provider) {
		taintProvider = provider;

		taintEnginePath = DEFAULT_TAINT_ENGINE_PATH;
		taintFactsDir = DEFAULT_TAINT_FACTS_DIR;
		taintOutputDir = DEFAULT_TAINT_OUTPUT_DIR;
		taintQuery = DEFAULT_TAINT_QUERY;
		taintDB = DEFAULT_TAINT_DB;
		taintQueryOutputForm = TaintFormat.ALL;
		taintQueryDirection = TaintDirection.DEFAULT;
		taintUseAllAccess = TAINT_ALL_ACCESS_PATHS;

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

		opt.registerOption(OP_KEY_TAINT_QUERY_OUTPUT_FORM, TaintFormat.ALL,
			new HelpLocation(HelpTopics.DECOMPILER, "Taint Output Type"),
			"The type of Source-Sink query output (e.g., sarif, summary, text)");

		opt.registerOption(OP_KEY_TAINT_QUERY_ENGINE, "",
			new HelpLocation(HelpTopics.DECOMPILER, "Taint Query Engine"),
			"The query engine (e.g., angr, ctadl)");

		opt.registerOption(OP_KEY_TAINT_ENGINE_PATH, DEFAULT_TAINT_ENGINE_PATH,
			new HelpLocation(HelpTopics.DECOMPILER, "Taint Engine Directory"),
			"Base path to external taint engine (Source-Sink executable).");

		opt.registerOption(OP_KEY_TAINT_FACTS_DIR, DEFAULT_TAINT_FACTS_DIR,
			new HelpLocation(HelpTopics.DECOMPILER, "Taint Facts Directory"),
			"Base Path to facts directory");

		opt.registerOption(OP_KEY_TAINT_OUTPUT_DIR, DEFAULT_TAINT_OUTPUT_DIR,
			new HelpLocation(HelpTopics.DECOMPILER, "Taint Output Directory"),
			"Base Path to output directory");

		opt.registerOption(OP_KEY_TAINT_QUERY, DEFAULT_TAINT_QUERY,
			new HelpLocation(HelpTopics.DECOMPILER, "TaintQuery"),
			"File where the query text that Ghidra produces is written.");

		opt.registerOption(OP_KEY_TAINT_DB, DEFAULT_TAINT_DB,
			new HelpLocation(HelpTopics.DECOMPILER, "Taint Database"),
			"File where the index is written for the binary.");

		opt.registerThemeColorBinding(TAINT_HIGHLIGHT, TAINT_HIGHLIGHT_COLOR.getId(),
			new HelpLocation(HelpTopics.DECOMPILER, "TaintTokenColor"),
			"Color used for highlighting tainted variables.");

		opt.registerOption(TAINT_ALL_ACCESS, TAINT_ALL_ACCESS_PATHS,
			new HelpLocation(HelpTopics.DECOMPILER, "TaintAllAccess"), "Use all access paths.");

		grabFromToolAndProgram(ownerPlugin, opt, program);
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

		String engine = opt.getString(OP_KEY_TAINT_QUERY_ENGINE, "").trim();
		if (!engine.equals(taintQueryEngine)) {
			TaintPlugin plugin = (TaintPlugin) ownerPlugin;
			TaintState state = TaintState.newInstance(plugin, engine);
			if (state != null) {
				plugin.setTaintState(state);
				taintQueryEngine = engine;
			}
		}
		
		taintEnginePath = opt.getString(OP_KEY_TAINT_ENGINE_PATH, "");
		taintFactsDir = opt.getString(OP_KEY_TAINT_FACTS_DIR, "");
		taintQuery = opt.getString(OP_KEY_TAINT_QUERY, "");
		// taintQueryResultsFile = opt.getString(OP_KEY_TAINT_QUERY_RESULTS, "");
		taintOutputDir = opt.getString(OP_KEY_TAINT_OUTPUT_DIR, "");
		taintDB = opt.getString(OP_KEY_TAINT_DB, "");

		taintQueryDirection = opt.getEnum(OP_KEY_TAINT_QUERY_DIRECTION, TaintDirection.DEFAULT);
		taintQueryOutputForm = opt.getEnum(OP_KEY_TAINT_QUERY_OUTPUT_FORM, TaintFormat.ALL);

		taintHighlightStyle = opt.getEnum(TAINT_HIGHLIGHT_STYLE, TAINT_HIGHLIGHT_STYLE_DEFAULT);
		taintHighlightColor = opt.getColor(TAINT_HIGHLIGHT, TAINT_HIGHLIGHT_COLOR);
		taintUseAllAccess = opt.getBoolean(TAINT_ALL_ACCESS, TAINT_ALL_ACCESS_PATHS);

	}

	public TaintFormat getTaintOutputForm() {
		return taintQueryOutputForm;
	}

	public String getTaintEngineType() {
		return taintQueryEngine;
	}

	public String getTaintEnginePath() {
		return taintEnginePath;
	}

	public String getTaintFactsDirectory() {
		return taintFactsDir;
	}

	public String getTaintOutputDirectory() {
		return taintOutputDir;
	}

	public String getTaintQueryDLName() {
		return taintQuery;
	}

	public String getTaintQueryDBName() {
		return taintDB;
	}

	public String getTaintQueryDBName(String name) {
		return makeDBName(taintDB, name);
	}

	public String getTaintIndexDBName() {
		return taintDB;
	}

	public String getTaintIndexDBName(String name) {
		return makeDBName(taintDB, name);
	}

	public Color getTaintHighlightColor() {
		return taintHighlightColor;
	}

	public Highlighter getTaintHighlightStyle() {
		return taintHighlightStyle;
	}

	public TaintDirection getTaintDirection() {
		return taintQueryDirection;
	}

	public Boolean getTaintUseAllAccess() {
		return taintUseAllAccess;
	}

	public void setTaintQueryEngine(String engine) {
		this.taintQueryEngine = engine;
		taintProvider.setOption(OP_KEY_TAINT_QUERY_ENGINE, engine);
	}

	public void setTaintOutputForm(TaintFormat form) {
		this.taintQueryOutputForm = form;
		taintProvider.setOption(OP_KEY_TAINT_QUERY_OUTPUT_FORM, form.getOptionString());
	}

	public void setTaintFactsDirectory(String path) {
		this.taintFactsDir = path;
		taintProvider.setOption(DEFAULT_TAINT_FACTS_DIR, path);
	}

	public void setTaintOutputDirectory(String path) {
		this.taintOutputDir = path;
		taintProvider.setOption(OP_KEY_TAINT_OUTPUT_DIR, path);
	}

	public void setTaintQueryName(String filename) {
		this.taintQuery = filename;
		taintProvider.setOption(OP_KEY_TAINT_QUERY, filename);
	}

	public void setTaintIndexDBName(String filename) {
		this.taintDB = filename;
		taintProvider.setOption(OP_KEY_TAINT_DB, filename);
	}

	public void setTaintHighlightColor(Color color) {
		this.taintHighlightColor = color;
		taintProvider.setColor(TAINT_HIGHLIGHT, color);
	}

	public void setTaintHighlightStyle(Highlighter style) {
		this.taintHighlightStyle = style;
		taintProvider.setOption(TAINT_HIGHLIGHT_STYLE, style.getOptionString());
		taintProvider.changeHighlighter(style);
	}

	public void setTaintDirection(TaintDirection direction) {
		this.taintQueryDirection = direction;
		taintProvider.setOption(OP_KEY_TAINT_QUERY_DIRECTION, direction.getOptionString());
	}

	public void setTaintAllAccess(Boolean allAccess) {
		this.taintUseAllAccess = allAccess;
	}
}
