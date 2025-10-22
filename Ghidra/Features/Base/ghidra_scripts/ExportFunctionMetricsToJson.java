/* ###
 * IP: GHIDRA
 * REVIEWED: NO
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
// Exports basic per-function metrics to a JSON file for the current program.
//@category Functions

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.Msg;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.data.DataType;
import ghidra.program.model.symbol.Namespace;

public class ExportFunctionMetricsToJson extends GhidraScript {

	@Override
	protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("No current program.");
			return;
		}

		File outFile = askFile("Choose output JSON file", "Save");
		if (outFile == null) {
			printerr("No output file selected.");
			return;
		}

		AddressSetView scope = currentSelection != null ? currentSelection : currentHighlight;
		writeFunctionMetricsJson(currentProgram, outFile, scope);
		println("Wrote function metrics to: " + outFile.getAbsolutePath());
	}

	private void writeFunctionMetricsJson(Program program, File outFile, AddressSetView scope)
			throws IOException {
		FunctionManager fm = program.getFunctionManager();
		Listing listing = program.getListing();
		CyclomaticComplexity complexityCalc = new CyclomaticComplexity();

		try (BufferedWriter w = new BufferedWriter(new FileWriter(outFile))) {
			w.write("{\n");
			// basic program info
			w.write("  \"program\": {\n");
			w.write("    \"name\": \"" + escape(program.getName()) + "\",\n");
			w.write("    \"language\": \"" + escape(program.getLanguageID().getIdAsString()) + "\"\n");
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

				// instruction count (iterate rather than rely on size for accuracy)
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

				// basic blocks (Simple block model over function body)
				int basicBlocks = 0;
				try {
					SimpleBlockModel model = new SimpleBlockModel(program);
					CodeBlockIterator blocks = model.getCodeBlocksContaining(body, monitor);
					while (blocks.hasNext() && !monitor.isCancelled()) {
						blocks.next();
						basicBlocks++;
					}
				}
				catch (CancelledException ce) {
					// respect cancellation; leave count as is
				}

				// locals count
				int localsCount = 0;
				try {
					if (!f.isExternal()) {
						localsCount = f.getLocalVariables().length;
					}
				}
				catch (Exception ignore) {
					// in some cases locals may not resolve; ignore
				}

				// signature and flags
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
}
