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

import java.io.*;
import java.lang.ProcessBuilder.Redirect;
import java.nio.file.Path;
import java.util.*;

import com.contrastsecurity.sarif.SarifSchema210;
import com.google.gson.JsonSyntaxException;

import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.decompiler.ClangToken;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeException;
import ghidra.util.Msg;
import sarif.SarifService;

/**
 * Container for all the decompiler elements the users "selects" via the menu.
 * This data is used to build queries.
 */
public abstract class AbstractTaintState implements TaintState {

	public static String ENGINE_NAME = "";

	private Set<TaintLabel> sources = new HashSet<>();
	private Set<TaintLabel> sinks = new HashSet<>();
	private Set<TaintLabel> gates = new HashSet<>();

	// Sets used for highlighting.
	private AddressSet taintAddressSet = new AddressSet();
	private Map<Address, Set<TaintQueryResult>> taintVarnodeMap = new HashMap<>();

	/// private QueryDataFrame currentQueryData;
	private SarifSchema210 currentQueryData;

	protected TaintOptions taintOptions;
	private TaintPlugin plugin;

	private boolean cancellation;

	public AbstractTaintState(TaintPlugin plugin) {
		this.plugin = plugin;
	}

	public abstract void buildQuery(List<String> param_list, Path engine, File indexDBFile,
			String index_directory);

	@Override
	public abstract void buildIndex(List<String> param_list, String engine_path, String facts_path,
			String index_path);

	protected abstract void writeRule(PrintWriter writer, TaintLabel mark, boolean isSource);

	protected abstract void writeGate(PrintWriter writer, TaintLabel mark);

	@Override
	public boolean wasCancelled() {
		return this.cancellation;
	}

	@Override
	public void setCancellation(boolean status) {
		this.cancellation = status;
	}

	@Override
	public Set<TaintLabel> getTaintLabels(MarkType mtype) {
		return switch (mtype) {
			case SOURCE -> sources;
			case SINK -> sinks;
			case GATE -> gates;
			default -> new HashSet<>();
		};
	}

	@Override
	public TaintLabel toggleMark(MarkType mtype, ClangToken token) throws PcodeException {
		TaintLabel labelToToggle = new TaintLabel(mtype, token);

		Msg.info(this, "labelToToggle: " + labelToToggle);
		Set<TaintLabel> marks = getTaintLabels(mtype);

		return updateMarks(labelToToggle, marks);
	}

	private TaintLabel updateMarks(TaintLabel tlabel, Set<TaintLabel> marks) {
		for (TaintLabel existingLabel : marks) {
			if (existingLabel.equals(tlabel)) {
				existingLabel.toggle();
				plugin.getTool().contextChanged(plugin.getDecompilerProvider());
				return existingLabel;
			}
		}

		marks.add(tlabel);
		plugin.getTool().contextChanged(plugin.getDecompilerProvider());
		return tlabel;
	}

	/**
	 * Predicate indicating the presence of one or more sources in the source set;
	 * this is used to determine state validity.
	 * 
	 * The source set MUST BE NON-EMPTY for a query to be executed.
	 */
	@Override
	public boolean isValid() {
		return activeSources() || activeSinks();
	}

	private boolean activeSinks() {
		for (TaintLabel label : sinks) {
			if (label.isActive())
				return true;
		}
		return false;
	}

	private boolean activeSources() {
		for (TaintLabel label : sources) {
			if (label.isActive())
				return true;
		}
		return false;
	}

	/**
	 * For the label table it doesn't matter which are active or inactive. We want
	 * to see all of them and the button should be active when we have any in these
	 * sets.
	 */
	@Override
	public boolean hasMarks() {
		return !sources.isEmpty() || !sinks.isEmpty() || !gates.isEmpty();
	}

	/**
	 * Write the datalog query file that the engine will use to generate results.
	 * 
	 * <p>
	 * The artifacts (e.g., sources) that are used in the datalog query are those
	 * selected by the user via the menu.
	 * 
	 * <p>
	 * @param queryTextFile - file containing the query
	 * @return success
	 * @throws Exception - on write
	 */
	public boolean writeQueryFile(File queryTextFile) throws Exception {

		PrintWriter writer = new PrintWriter(queryTextFile);
		writer.println("#include \"pcode/taintquery.dl\"");

		for (TaintLabel mark : sources) {
			if (mark.isActive()) {
				writeRule(writer, mark, true);
			}
		}

		writer.println("");

		for (TaintLabel mark : sinks) {
			if (mark.isActive()) {
				// CAREFUL note the "false"
				writeRule(writer, mark, false);
			}
		}

		if (!gates.isEmpty()) {
			writer.println("");
			for (TaintLabel mark : gates) {
				if (mark.isActive()) {
					writeGate(writer, mark);
				}
			}
		}

		writer.flush();
		writer.close();

		plugin.consoleMessage("Wrote Query File: " + queryTextFile);

		return true;
	}

	/**
	 * Build the query string, save it to a file the users selects, and run the
	 * engine using the index and the query that is saved to the file.
	 */
	@Override
	public boolean queryIndex(Program program, PluginTool tool, QueryType queryType) {

		if (queryType.equals(QueryType.SRCSINK) && !isValid()) {
			Msg.showWarn(this, tool.getActiveWindow(), getName() + " Query Warning",
				getName() + " query cannot be performed because there are no sources or sinks.");
			return false;
		}

		List<String> param_list = new ArrayList<String>();
		File queryFile = null;
		taintOptions = plugin.getOptions();

		try {

			// Make sure we can access and execute the engine binary.
			Path engine = Path.of(taintOptions.getTaintEnginePath());
			File engine_file = engine.toFile();

			if (!engine_file.exists() || !engine_file.canExecute()) {
				plugin.consoleMessage("The " + getName() + " binary (" +
					engine_file.getCanonicalPath() + ") cannot be found or executed.");
				engine_file = getFilePath(taintOptions.getTaintEnginePath(),
					"Select the " + getName() + " binary");
				if (engine_file == null) {
					plugin.consoleMessage(
						"No " + getName() + " engine has been specified; exiting query function.");
					return false;
				}
			}

			plugin.consoleMessage("Using " + getName() + " binary: " + engine_file.toString());

			Path index_directory = Path.of(taintOptions.getTaintOutputDirectory());
			Path indexDBPath = Path.of(taintOptions.getTaintOutputDirectory(),
				taintOptions.getTaintIndexDBName(program.getName()));

			File indexDBFile = indexDBPath.toFile();
			plugin.consoleMessage("Attempting to use index: " + indexDBFile.toString());

			if (!indexDBFile.exists()) {
				plugin.consoleMessage("The index database for the binary named: " +
					program.getName() + " does not exist; create it first.");
				return false;
			}

			plugin.consoleMessage("Using index database: " + indexDBFile);

			switch (queryType) {
				case SRCSINK:
					// Generate a datalog query file based on the selected source, sink, etc. data.
					// This file can be overwritten
					Path queryPath = Path.of(taintOptions.getTaintOutputDirectory(),
						taintOptions.getTaintQueryDLName());
					queryFile = queryPath.toFile();
					writeQueryFile(queryFile);
					plugin.consoleMessage("The datalog query file: " + queryFile.toString() +
						" has been written and can be referenced later if needed.");
					break;
				case DEFAULT:
					plugin.consoleMessage("Performing default query.");
					break;
				case CUSTOM:
					plugin.consoleMessage("Performing custom query.");
					break;
				default:
					plugin.consoleMessage("Unknown query type.");
			}

			buildQuery(param_list, engine, indexDBFile, index_directory.toString());

			if (queryType.equals(QueryType.SRCSINK) || queryType.equals(QueryType.CUSTOM)) {
				// The datalog that specifies the query.
				if (queryType.equals(QueryType.CUSTOM)) {
					Path queryPath = Path.of(taintOptions.getTaintOutputDirectory(),
						taintOptions.getTaintQueryDLName());
					queryFile = queryPath.toFile();
				}
				param_list.add(queryFile.getAbsolutePath());
			}

			Msg.info(this, "Query Param List: " + param_list.toString());
			try {
				ProcessBuilder pb = new ProcessBuilder(param_list);
				pb.directory(new File(taintOptions.getTaintOutputDirectory()));
				pb.redirectError(Redirect.INHERIT);
				Process p = pb.start();

				switch (taintOptions.getTaintOutputForm()) {
					case "sarif+all":
						readQueryResultsIntoDataFrame(program, p.getInputStream());
						break;
					default:
				}
				// We wait for the process to finish after starting to read the input stream,
				// otherwise waitFor() might wait for a running process trying to write to 
				// a filled output buffer. This causes waitFor() to wait indefinitely.
				p.waitFor();

			}
			catch (InterruptedException e) {
				Msg.error(this, e.getMessage());
				return false;
			}

		}
		catch (Exception e) {
			Msg.error(this, "Problems running query: " + e);
			return false;
		}
		return true;
	}

	/**
	 * @param is the input stream (SARIF json) from the process builder that runs the engine
	 */
	private void readQueryResultsIntoDataFrame(Program program, InputStream is) {

		StringBuilder sb = new StringBuilder();
		String line = null;
		taintAddressSet.clear();
		taintVarnodeMap.clear();

		try {
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(is));

			while ((line = bufferedReader.readLine()) != null) {
				sb.append(line);
			}
			bufferedReader.close();
		}
		catch (IOException e) {
			plugin.consoleMessage("IO Error Reading Query Results from Process: " + e.getMessage());
		}

		try {
			currentQueryData = plugin.getSarifService().readSarif(sb.toString());
		}
		catch (JsonSyntaxException e) {
			plugin.consoleMessage(
				"Error in JSON in Sarif Output from " + getName() + ": " + e.getMessage());
			e.printStackTrace();
		}
		catch (IOException e) {
			plugin.consoleMessage(
				"IO Exception Parsing JSON Sarif Output from " + getName() + ": " + e.getMessage());
			e.printStackTrace();
		}
	}

	private File getFilePath(String initial_directory, String title) {

		GhidraFileChooser chooser = new GhidraFileChooser(null);
		chooser.setCurrentDirectory(new File(initial_directory));
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setTitle(title);
		File selectedFile = chooser.getSelectedFile();
		if (selectedFile != null) {
			return selectedFile;
		}

		return selectedFile;
	}

	/**
	 * Read and parse a file that has Sarif JSON in it and set the addresses in the
	 * listing that are tainted so they are highlighted.
	 * 
	 * @param sarifFile a file that contains SARIF JSON data.
	 */
	@Override
	public void loadTaintData(Program program, File sarifFile) {

		try {
			//SarifTaintGraphRunHandler.setEnabled(true);
			SarifService sarifService = plugin.getSarifService();
			SarifSchema210 sarif_data = sarifService.readSarif(sarifFile);
			sarifService.showSarif(sarifFile.getName(), sarif_data);
		}
		catch (JsonSyntaxException e) {
			plugin.consoleMessage(
				"Syntax error in JSON taint data " + getName() + ": " + e.getMessage());
			e.printStackTrace();
		}
		catch (IOException e) {
			plugin.consoleMessage(
				"IO Exception parsing in JSON taint data " + getName() + ": " + e.getMessage());
			e.printStackTrace();
		}
	}

	@Override
	public void setTaintAddressSet(AddressSet aset) {
		taintAddressSet = aset;
	}

	@Override
	public AddressSet getTaintAddressSet() {
		return taintAddressSet;
	}

	@Override
	public void augmentAddressSet(ClangToken token) {
		Address addr = token.getMinAddress();
		if (addr != null) {
			taintAddressSet.add(addr);
		}
	}

	@Override
	public void setTaintVarnodeMap(Map<Address, Set<TaintQueryResult>> vmap) {
		taintVarnodeMap = vmap;
	}

	@Override
	public Map<Address, Set<TaintQueryResult>> getTaintVarnodeMap() {
		return taintVarnodeMap;
	}

	@Override
	public void clearTaint() {
		Msg.info(this, "TaintState: clearTaint() - clearing address set");
		taintAddressSet.clear();
		taintVarnodeMap.clear();
	}

	@Override
	public void clearMarkers() {
		sources.clear();
		sinks.clear();
		gates.clear();
	}

	@Override
	public boolean isSink(HighVariable hvar) {
		for (TaintLabel mark : sinks) {
			if (mark.getHighVariable() != null && mark.getHighVariable().equals(hvar)) {
				return true;
			}
		}
		return false;
	}

	@Override
	public SarifSchema210 getData() {
		if (currentQueryData == null) {
			Msg.warn(this, "attempt to retrieve a sarif data frame that is null.");
		}
		return currentQueryData;
	}

	@Override
	public void clearData() {
		currentQueryData = null;
	}

	@Override
	public TaintOptions getOptions() {
		return plugin.getOptions();
	}

	public String getName() {
		return ENGINE_NAME;
	}

}
