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

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.*;
import com.google.gson.stream.JsonWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;

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

		// Ask user to choose export format
		List<ExportFormat> formats = Arrays.asList(ExportFormat.values());
		ExportFormat selectedFormat = askChoice("Choose Export Format",
				"Select the format for exporting function information:", formats, ExportFormat.JSON_SIMPLE);

		// Determine file extension based on format
		String extension;
		switch (selectedFormat) {
			case JSON_SIMPLE:
			case JSON_METRICS:
				extension = ".json";
				break;
			case CSV_METRICS:
				extension = ".csv";
				break;
			case DOT_CALLGRAPH:
				extension = ".dot";
				break;
			default:
				extension = ".txt";
				break;
		}

		File outputFile = askFile("Please Select Output File", "Choose");
		if (outputFile == null) {
			printerr("No output file selected.");
			return;
		}

		// Get optional scope (selection or highlight)
		AddressSetView scope = currentSelection != null ? currentSelection : currentHighlight;

		// Export based on selected format
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

	// ========== SIMPLE JSON EXPORT ==========
	private void exportSimpleJson(File outputFile, AddressSetView scope) throws Exception {
		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		try (JsonWriter jsonWriter = new JsonWriter(new FileWriter(outputFile))) {
		jsonWriter.beginArray();

		Listing listing = currentProgram.getListing();
		FunctionIterator iter = listing.getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();

				// Apply scope filtering if present
				if (scope != null && !scope.intersects(f.getBody())) {
					continue;
				}

			String name = f.getName();
			Address entry = f.getEntryPoint();

			JsonObject json = new JsonObject();
			json.addProperty(NAME, name);
			json.addProperty(ENTRY, entry.toString());

			gson.toJson(json, jsonWriter);
		}

		jsonWriter.endArray();
		}
	}

	// ========== DETAILED JSON METRICS EXPORT ==========
	private void exportMetricsJson(File outputFile, AddressSetView scope) throws IOException {
		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();
		CyclomaticComplexity complexityCalc = new CyclomaticComplexity();

		try (BufferedWriter w = new BufferedWriter(new FileWriter(outputFile))) {
			w.write("{\n");
			// Basic program info
			w.write("  \"program\": {\n");
			w.write("    \"name\": \"" + escape(currentProgram.getName()) + "\",\n");
			w.write("    \"language\": \"" + escape(currentProgram.getLanguageID().getIdAsString()) + "\"\n");
			w.write("  },\n");
			w.write("  \"functions\": [\n");

			FunctionIterator it = fm.getFunctions(true);
			boolean first = true;
			monitor.initialize(fm.getFunctionCount());
			int exported = 0;

			while (it.hasNext() && !monitor.isCancelled()) {
				Function f = it.next();
				AddressSetView body = f.getBody();
				if (scope != null && !scope.intersects(body)) {
					continue;
				}

				monitor.setMessage("Exporting metrics: " + f.getName());
				monitor.incrementProgress(1);
				if (!first) {
					w.write(",\n");
				}
				first = false;

				String entry = f.getEntryPoint().toString();
				long size = body.getNumAddresses();

				// Instruction count
				int instCount = 0;
				for (Iterator<Instruction> insIt = listing.getInstructions(body, true); insIt.hasNext();) {
					insIt.next();
					instCount++;
				}

				int callers = sizeSafe(f.getCallingFunctions(monitor));
				int callees = sizeSafe(f.getCalledFunctions(monitor));

				int cplx = 0;
				try {
					cplx = complexityCalc.calculateCyclomaticComplexity(f, monitor);
				}
				catch (Exception e) {
					Msg.warn(this, "Failed to compute complexity for " + f.getName(), e);
				}

				int params = f.getParameterCount();

				// Basic blocks
				int basicBlocks = 0;
				try {
					SimpleBlockModel model = new SimpleBlockModel(currentProgram);
					CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
					while (blocks.hasNext() && !monitor.isCancelled()) {
						blocks.next();
						basicBlocks++;
					}
				}
				catch (CancelledException ce) {
					// Respect cancellation; leave count as is
				}

				// Locals count
				int localsCount = 0;
				try {
					if (!f.isExternal()) {
						localsCount = f.getLocalVariables().length;
					}
				}
				catch (Exception ignore) {
					// In some cases locals may not resolve; ignore
				}

				// Signature and flags
				boolean isExternal = f.isExternal();
				boolean isThunk = f.isThunk();
				boolean hasVarArgs = f.hasVarArgs();
				boolean isInline = f.isInline();
				boolean noReturn = f.hasNoReturn();
				boolean customStorage = f.hasCustomVariableStorage();
				int stackPurgeSize = f.getStackPurgeSize();
				String callConv = safeString(f.getCallingConventionName());
				Namespace ns = f.getParentNamespace();
				String namespace = ns != null ? ns.getName(true) : "";
				DataType retType = f.getReturnType();
				String returnType = retType != null ? retType.getDisplayName() : "void";
				String proto = f.getPrototypeString(true, false);
				String protoWithCc = f.getPrototypeString(true, true);
				String thunkTarget = null;
				if (isThunk) {
					Function tf = f.getThunkedFunction(true);
					if (tf != null) {
						thunkTarget = tf.getEntryPoint().toString();
					}
				}

				w.write("    {\n");
				w.write("      \"name\": \"" + escape(f.getName()) + "\",\n");
				w.write("      \"entry\": \"" + escape(entry) + "\",\n");
				w.write("      \"size_bytes\": " + size + ",\n");
				w.write("      \"address_ranges\": " + body.getNumAddressRanges() + ",\n");
				w.write("      \"instruction_count\": " + instCount + ",\n");
				w.write("      \"cyclomatic_complexity\": " + cplx + ",\n");
				w.write("      \"parameters\": " + params + ",\n");
				w.write("      \"locals\": " + localsCount + ",\n");
				w.write("      \"basic_blocks\": " + basicBlocks + ",\n");
				w.write("      \"external\": " + isExternal + ",\n");
				w.write("      \"thunk\": " + isThunk + ",\n");
				w.write("      \"thunk_target\": " + (thunkTarget == null ? "null" : ("\"" + escape(thunkTarget) + "\"")) + ",\n");
				w.write("      \"variadic\": " + hasVarArgs + ",\n");
				w.write("      \"inline\": " + isInline + ",\n");
				w.write("      \"no_return\": " + noReturn + ",\n");
				w.write("      \"custom_storage\": " + customStorage + ",\n");
				w.write("      \"stack_purge_size\": " + stackPurgeSize + ",\n");
				w.write("      \"calling_convention\": \"" + escape(callConv) + "\",\n");
				w.write("      \"namespace\": \"" + escape(namespace) + "\",\n");
				w.write("      \"return_type\": \"" + escape(returnType) + "\",\n");
				w.write("      \"prototype\": \"" + escape(proto) + "\",\n");
				w.write("      \"prototype_with_cc\": \"" + escape(protoWithCc) + "\",\n");
				w.write("      \"callers\": " + callers + ",\n");
				w.write("      \"callees\": " + callees + "\n");
				w.write("    }");
				exported++;
			}

			w.write("\n  ],\n");
			w.write("  \"summary\": {\n");
			w.write("    \"exported_functions\": " + exported + ",\n");
			w.write("    \"total_functions\": " + fm.getFunctionCount() + ",\n");
			w.write("    \"selection_applied\": " + Boolean.toString(scope != null) + "\n");
			w.write("  }\n");
			w.write("}\n");
		}
	}

	// ========== CSV METRICS EXPORT ==========
	private void exportMetricsCsv(File outputFile, AddressSetView scope) throws IOException {
		FunctionManager fm = currentProgram.getFunctionManager();
		Listing listing = currentProgram.getListing();
		CyclomaticComplexity complexityCalc = new CyclomaticComplexity();

		try (BufferedWriter w = new BufferedWriter(new FileWriter(outputFile))) {
			// Header
			w.write(String.join(",",
				"name","entry","address_ranges","instruction_count","cyclomatic_complexity",
				"parameters","locals","basic_blocks","external","thunk","thunk_target",
				"variadic","inline","no_return","custom_storage","stack_purge_size",
				"calling_convention","namespace","return_type","prototype","prototype_with_cc",
				"callers","callees"));
			w.write("\n");

			FunctionIterator it = fm.getFunctions(true);
			monitor.initialize(fm.getFunctionCount());

			while (it.hasNext() && !monitor.isCancelled()) {
				Function f = it.next();
				AddressSetView body = f.getBody();
				if (scope != null && !scope.intersects(body)) {
					continue;
				}

				monitor.setMessage("Exporting metrics: " + f.getName());
				monitor.incrementProgress(1);

				String entry = f.getEntryPoint().toString();

				// Instruction count
				int instCount = 0;
				for (Iterator<Instruction> insIt = listing.getInstructions(body, true); insIt.hasNext();) {
					insIt.next();
					instCount++;
				}

				int callers = sizeSafe(f.getCallingFunctions(monitor));
				int callees = sizeSafe(f.getCalledFunctions(monitor));

				int cplx = 0;
				try {
					cplx = complexityCalc.calculateCyclomaticComplexity(f, monitor);
				}
				catch (Exception e) {
					Msg.warn(this, "Failed to compute complexity for " + f.getName(), e);
				}

				int params = f.getParameterCount();

				// Basic blocks
				int basicBlocks = 0;
				try {
					SimpleBlockModel model = new SimpleBlockModel(currentProgram);
					CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
					while (blocks.hasNext() && !monitor.isCancelled()) {
						blocks.next();
						basicBlocks++;
					}
				}
				catch (CancelledException ce) {
					// Respect cancellation
				}

				int localsCount = 0;
				try {
					if (!f.isExternal()) {
						localsCount = f.getLocalVariables().length;
					}
				}
				catch (Exception ignore) {
				}

				boolean isExternal = f.isExternal();
				boolean isThunk = f.isThunk();
				boolean hasVarArgs = f.hasVarArgs();
				boolean isInline = f.isInline();
				boolean noReturn = f.hasNoReturn();
				boolean customStorage = f.hasCustomVariableStorage();
				int stackPurgeSize = f.getStackPurgeSize();
				String callConv = safeString(f.getCallingConventionName());
				Namespace ns = f.getParentNamespace();
				String namespace = ns != null ? ns.getName(true) : "";
				DataType retType = f.getReturnType();
				String returnType = retType != null ? retType.getDisplayName() : "void";
				String proto = f.getPrototypeString(true, false);
				String protoWithCc = f.getPrototypeString(true, true);
				String thunkTarget = null;
				if (isThunk) {
					Function tf = f.getThunkedFunction(true);
					if (tf != null) {
						thunkTarget = tf.getEntryPoint().toString();
					}
				}

				w.write(String.join(",",
					csv(f.getName()), csv(entry),
					Integer.toString(body.getNumAddressRanges()),
					Integer.toString(instCount), Integer.toString(cplx),
					Integer.toString(params), Integer.toString(localsCount),
					Integer.toString(basicBlocks), Boolean.toString(isExternal),
					Boolean.toString(isThunk), csvOrEmpty(thunkTarget),
					Boolean.toString(hasVarArgs), Boolean.toString(isInline),
					Boolean.toString(noReturn), Boolean.toString(customStorage),
					Integer.toString(stackPurgeSize), csv(callConv), csv(namespace),
					csv(returnType), csv(proto), csv(protoWithCc),
					Integer.toString(callers), Integer.toString(callees)));
				w.write("\n");
			}
		}
	}

	// ========== DOT CALL GRAPH EXPORT ==========
	private void exportCallGraphDot(File outputFile, AddressSetView scope) throws IOException {
		FunctionManager fm = currentProgram.getFunctionManager();
		FunctionIterator it = fm.getFunctions(true);

		Map<String, Integer> idByEntry = new HashMap<>();
		Set<String> edges = new HashSet<>();
		int nextId = 1;

		monitor.initialize(fm.getFunctionCount());

		while (it.hasNext() && !monitor.isCancelled()) {
			Function f = it.next();
			if (scope != null && !scope.intersects(f.getBody())) {
				continue;
			}
			monitor.setMessage("Indexing function: " + f.getName());
			monitor.incrementProgress(1);

			String fEntry = f.getEntryPoint().toString();
			idByEntry.computeIfAbsent(fEntry, k -> nextId++);

			for (Function callee : f.getCalledFunctions(monitor)) {
				if (scope != null && !scope.intersects(callee.getBody())) {
					// If filtered by selection, only keep edges entirely in scope
					continue;
				}
				String cEntry = callee.getEntryPoint().toString();
				idByEntry.computeIfAbsent(cEntry, k -> nextId++);
				edges.add(fEntry + "->" + cEntry);
			}
		}

		try (BufferedWriter w = new BufferedWriter(new FileWriter(outputFile))) {
			w.write("digraph \"" + escape(currentProgram.getName()) + "\" {\n");
			w.write("  node [shape=box, fontsize=10];\n");

			for (Map.Entry<String, Integer> e : idByEntry.entrySet()) {
				String entry = e.getKey();
				int id = e.getValue();
				// Label: function name + entry
				Function f = fm.getFunctionAt(currentProgram.getAddressFactory().getAddress(entry));
				String label = (f != null ? f.getName() : entry) + "\\n" + entry;
				w.write("  n" + id + " [label=\"" + escape(label) + "\"];\n");
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

	// ========== HELPER METHODS ==========
	private static int sizeSafe(Set<?> s) {
		return s == null ? 0 : s.size();
	}

	private static String safeString(String s) {
		return s == null ? "" : s;
	}

	private static String escape(String s) {
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
				case '\b':
					b.append("\\b");
					break;
				case '\f':
					b.append("\\f");
					break;
				case '\n':
					b.append("\\n");
					break;
				case '\r':
					b.append("\\r");
					break;
				case '\t':
					b.append("\\t");
					break;
				default:
					if (c < 0x20) {
						appendUnicodeEscape(b, c);
					}
					else {
						b.append(c);
					}
					break;
			}
		}
		return b.toString();
	}

	private static void appendUnicodeEscape(StringBuilder b, char c) {
		b.append("\\u");
		String hex = Integer.toHexString(c);
		for (int i = hex.length(); i < 4; i++) {
			b.append('0');
		}
		b.append(hex);
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
