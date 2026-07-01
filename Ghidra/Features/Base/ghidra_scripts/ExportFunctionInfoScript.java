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
// Export function information in various formats (JSON, CSV, DOT)
//@category Functions

import java.io.*;
import java.util.*;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import util.CollectionUtils;

public class ExportFunctionInfoScript extends GhidraScript {

	private static final String NAME = "name";
	private static final String ENTRY = "entry";

	private enum ExportFormat {
		JSON_SIMPLE("JSON (Simple - name and entry only)"),
		JSON_METRICS("JSON (Detailed metrics)"),
		CSV_METRICS("CSV (Detailed metrics)"),
		DOT_CALLGRAPH("DOT (Function call graph)");

		private final String displayName;

		ExportFormat(String displayName) {
			this.displayName = displayName;
		}

		@Override
		public String toString() {
			return displayName;
		}
	}

	@Override
	public void run() throws Exception {
		if (currentProgram == null) {
			printerr("No current program.");
			return;
		}

		List<ExportFormat> formats = Arrays.asList(ExportFormat.values());
		ExportFormat selectedFormat = askChoice("Choose Export Format",
			"Select the format for exporting function information:", formats,
			ExportFormat.JSON_SIMPLE);

		File outputFile = askFile("Please Select Output File", "Choose");
		if (outputFile == null) {
			printerr("No output file selected.");
			return;
		}

		AddressSetView scope = currentSelection != null ? currentSelection : currentHighlight;

		switch (selectedFormat) {
			case JSON_SIMPLE:
				exportSimpleJson(outputFile, scope);
				break;
			case JSON_METRICS:
				exportMetricsJson(outputFile, scope);
				break;
			case CSV_METRICS:
				exportMetricsCsv(outputFile, scope);
				break;
			case DOT_CALLGRAPH:
				exportCallGraphDot(outputFile, scope);
				break;
		}

		println("Wrote function information to: " + outputFile.getAbsolutePath());
	}

	private void exportSimpleJson(File outputFile, AddressSetView scope)
			throws IOException, CancelledException {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		try (JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile))) {
			jsonWriter.beginArray();

			Listing listing = currentProgram.getListing();
			FunctionIterator iter = listing.getFunctions(true);
			while (iter.hasNext()) {
				monitor.checkCancelled();
				Function f = iter.next();

				if (scope != null && !scope.intersects(f.getBody())) {
					continue;
				}

				JsonObject json = new JsonObject();
				json.addProperty(NAME, f.getName());
				json.addProperty(ENTRY, f.getEntryPoint().toString());

				gson.toJson(json, jsonWriter);
			}

			jsonWriter.endArray();
		}
	}

	private void exportMetricsJson(File outputFile, AddressSetView scope)
			throws IOException, CancelledException {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();
		FunctionManager fm = currentProgram.getFunctionManager();
		CyclomaticComplexity complexityCalc = new CyclomaticComplexity();

		JsonObject root = new JsonObject();

		JsonObject programInfo = new JsonObject();
		programInfo.addProperty("name", currentProgram.getName());
		programInfo.addProperty("language", currentProgram.getLanguageID().getIdAsString());
		root.add("program", programInfo);

		JsonArray functions = new JsonArray();
		FunctionIterator it = fm.getFunctions(true);
		monitor.initialize(fm.getFunctionCount());
		int exported = 0;

		while (it.hasNext()) {
			monitor.checkCancelled();
			Function f = it.next();
			AddressSetView body = f.getBody();
			if (scope != null && !scope.intersects(body)) {
				continue;
			}

			monitor.setMessage("Exporting metrics: " + f.getName());
			monitor.incrementProgress(1);

			functions.add(buildFunctionMetricsJson(f, body, complexityCalc));
			exported++;
		}

		root.add("functions", functions);

		JsonObject summary = new JsonObject();
		summary.addProperty("exported_functions", exported);
		summary.addProperty("total_functions", fm.getFunctionCount());
		summary.addProperty("selection_applied", scope != null);
		root.add("summary", summary);

		try (FileWriter w = new FileWriter(outputFile)) {
			gson.toJson(root, w);
		}
	}

	private JsonObject buildFunctionMetricsJson(Function f, AddressSetView body,
			CyclomaticComplexity complexityCalc) throws CancelledException {
		Listing listing = currentProgram.getListing();

		int instCount = (int) CollectionUtils.asStream(listing.getInstructions(body, true))
			.count();
		int callers = sizeSafe(f.getCallingFunctions(monitor));
		int callees = sizeSafe(f.getCalledFunctions(monitor));

		int cplx = 0;
		try {
			cplx = complexityCalc.calculateCyclomaticComplexity(f, monitor);
		}
		catch (Exception e) {
			Msg.warn(this, "Failed to compute complexity for " + f.getName(), e);
		}

		int localsCount = 0;
		if (!f.isExternal()) {
			localsCount = f.getLocalVariables().length;
		}

		String thunkTarget = null;
		if (f.isThunk()) {
			Function tf = f.getThunkedFunction(true);
			if (tf != null) {
				thunkTarget = tf.getEntryPoint().toString();
			}
		}

		Namespace ns = f.getParentNamespace();
		DataType retType = f.getReturnType();

		JsonObject json = new JsonObject();
		json.addProperty("name", f.getName());
		json.addProperty("entry", f.getEntryPoint().toString());
		json.addProperty("size_bytes", body.getNumAddresses());
		json.addProperty("address_ranges", body.getNumAddressRanges());
		json.addProperty("instruction_count", instCount);
		json.addProperty("cyclomatic_complexity", cplx);
		json.addProperty("parameters", f.getParameterCount());
		json.addProperty("locals", localsCount);
		json.addProperty("basic_blocks", getBasicBlockCount(body));
		json.addProperty("external", f.isExternal());
		json.addProperty("thunk", f.isThunk());
		if (thunkTarget == null) {
			json.add("thunk_target", JsonNull.INSTANCE);
		}
		else {
			json.addProperty("thunk_target", thunkTarget);
		}
		json.addProperty("variadic", f.hasVarArgs());
		json.addProperty("inline", f.isInline());
		json.addProperty("no_return", f.hasNoReturn());
		json.addProperty("custom_storage", f.hasCustomVariableStorage());
		json.addProperty("stack_purge_size", f.getStackPurgeSize());
		json.addProperty("calling_convention", safeString(f.getCallingConventionName()));
		json.addProperty("namespace", ns != null ? ns.getName(true) : "");
		json.addProperty("return_type",
			retType != null ? retType.getDisplayName() : "void");
		json.addProperty("prototype", f.getPrototypeString(true, false));
		json.addProperty("prototype_with_cc", f.getPrototypeString(true, true));
		json.addProperty("callers", callers);
		json.addProperty("callees", callees);
		return json;
	}

	private void exportMetricsCsv(File outputFile, AddressSetView scope)
			throws IOException, CancelledException {
		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();
		CyclomaticComplexity complexityCalc = new CyclomaticComplexity();

		try (BufferedWriter w = new BufferedWriter(new FileWriter(outputFile))) {
			w.write(String.join(",", "name", "entry", "address_ranges", "instruction_count",
				"cyclomatic_complexity", "parameters", "locals", "basic_blocks", "external",
				"thunk", "thunk_target", "variadic", "inline", "no_return", "custom_storage",
				"stack_purge_size", "calling_convention", "namespace", "return_type",
				"prototype", "prototype_with_cc", "callers", "callees"));
			w.write("\n");

			FunctionIterator it = fm.getFunctions(true);
			monitor.initialize(fm.getFunctionCount());

			while (it.hasNext()) {
				monitor.checkCancelled();
				Function f = it.next();
				AddressSetView body = f.getBody();
				if (scope != null && !scope.intersects(body)) {
					continue;
				}

				monitor.setMessage("Exporting metrics: " + f.getName());
				monitor.incrementProgress(1);

				String entry = f.getEntryPoint().toString();
				int instCount = (int) CollectionUtils.asStream(listing.getInstructions(body, true))
					.count();

				int callers = sizeSafe(f.getCallingFunctions(monitor));
				int callees = sizeSafe(f.getCalledFunctions(monitor));

				int cplx = 0;
				try {
					cplx = complexityCalc.calculateCyclomaticComplexity(f, monitor);
				}
				catch (Exception e) {
					Msg.warn(this, "Failed to compute complexity for " + f.getName(), e);
				}

				int localsCount = 0;
				if (!f.isExternal()) {
					localsCount = f.getLocalVariables().length;
				}

				String thunkTarget = null;
				if (f.isThunk()) {
					Function tf = f.getThunkedFunction(true);
					if (tf != null) {
						thunkTarget = tf.getEntryPoint().toString();
					}
				}

				Namespace ns = f.getParentNamespace();
				String namespace = ns != null ? ns.getName(true) : "";
				DataType retType = f.getReturnType();
				String returnType = retType != null ? retType.getDisplayName() : "void";
				String callConv = safeString(f.getCallingConventionName());
				String proto = f.getPrototypeString(true, false);
				String protoWithCc = f.getPrototypeString(true, true);

				w.write(String.join(",", csv(f.getName()), csv(entry),
					Integer.toString(body.getNumAddressRanges()), Integer.toString(instCount),
					Integer.toString(cplx), Integer.toString(f.getParameterCount()),
					Integer.toString(localsCount), Integer.toString(getBasicBlockCount(body)),
					Boolean.toString(f.isExternal()), Boolean.toString(f.isThunk()),
					csvOrEmpty(thunkTarget), Boolean.toString(f.hasVarArgs()),
					Boolean.toString(f.isInline()), Boolean.toString(f.hasNoReturn()),
					Boolean.toString(f.hasCustomVariableStorage()),
					Integer.toString(f.getStackPurgeSize()), csv(callConv), csv(namespace),
					csv(returnType), csv(proto), csv(protoWithCc),
					Integer.toString(callers), Integer.toString(callees)));
				w.write("\n");
			}
		}
	}

	private void exportCallGraphDot(File outputFile, AddressSetView scope)
			throws IOException, CancelledException {
		FunctionManager fm = currentProgram.getFunctionManager();
		FunctionIterator it = fm.getFunctions(true);

		Map<String, Integer> idByEntry = new HashMap<>();
		Set<String> edges = new HashSet<>();

		monitor.initialize(fm.getFunctionCount());

		while (it.hasNext()) {
			monitor.checkCancelled();
			Function f = it.next();
			if (scope != null && !scope.intersects(f.getBody())) {
				continue;
			}
			monitor.setMessage("Indexing function: " + f.getName());
			monitor.incrementProgress(1);

			String fEntry = f.getEntryPoint().toString();
			assignFunctionId(idByEntry, fEntry);

			for (Function callee : f.getCalledFunctions(monitor)) {
				monitor.checkCancelled();
				if (scope != null && !scope.intersects(callee.getBody())) {
					continue;
				}
				String cEntry = callee.getEntryPoint().toString();
				assignFunctionId(idByEntry, cEntry);
				edges.add(fEntry + "->" + cEntry);
			}
		}

		try (BufferedWriter w = new BufferedWriter(new FileWriter(outputFile))) {
			w.write("digraph \"" + escapeDot(currentProgram.getName()) + "\" {\n");
			w.write("  node [shape=box, fontsize=10];\n");

			for (Map.Entry<String, Integer> e : idByEntry.entrySet()) {
				String entry = e.getKey();
				int id = e.getValue();
				Function f =
					fm.getFunctionAt(currentProgram.getAddressFactory().getAddress(entry));
				String name = f != null ? f.getName() : entry;
				String label = name + "\n" + entry;
				w.write("  n" + id + " [label=\"" + escapeDot(label) + "\"];\n");
			}

			for (String edge : edges) {
				String[] parts = edge.split("->", 2);
				Integer sId = idByEntry.get(parts[0]);
				Integer tId = idByEntry.get(parts[1]);
				if (sId != null && tId != null) {
					w.write("  n" + sId + " -> n" + tId + ";\n");
				}
			}

			w.write("}\n");
		}
	}

	private int getBasicBlockCount(AddressSetView body) throws CancelledException {
		SimpleBlockModel model = new SimpleBlockModel(currentProgram);
		CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
		int basicBlocks = 0;
		while (blocks.hasNext()) {
			monitor.checkCancelled();
			blocks.next();
			basicBlocks++;
		}
		return basicBlocks;
	}

	private static void assignFunctionId(Map<String, Integer> idByEntry, String entry) {
		if (!idByEntry.containsKey(entry)) {
			idByEntry.put(entry, idByEntry.size() + 1);
		}
	}

	private static int sizeSafe(Set<?> s) {
		return s == null ? 0 : s.size();
	}

	private static String safeString(String s) {
		return s == null ? "" : s;
	}

	private static String escapeDot(String s) {
		if (s == null) {
			return "";
		}
		StringBuilder b = new StringBuilder(s.length() + 16);
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			switch (c) {
				case '"':
					b.append("\\\"");
					break;
				case '\\':
					b.append("\\\\");
					break;
				case '\n':
					b.append("\\n");
					break;
				default:
					b.append(c);
					break;
			}
		}
		return b.toString();
	}

	private static String csv(String s) {
		if (s == null) {
			return "\"\"";
		}
		String v = s.replace("\"", "\"\"");
		return "\"" + v + "\"";
	}

	private static String csvOrEmpty(String s) {
		return s == null ? "" : csv(s);
	}
}
