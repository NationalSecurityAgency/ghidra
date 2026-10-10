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
package ghidra.ai;

import java.util.*;
import java.util.function.Function;

import com.google.gson.JsonObject;

import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

/**
 * The tools the AI can call to investigate the open program: searching functions, strings and
 * symbols, following references, decompiling, disassembling and navigating the listing. Every
 * tool is read-only except {@code go_to}, which only moves the cursor.
 */
class AITools {

	/** Tool description in a provider-neutral form (JSON-schema style parameters). */
	record ToolSpec(String name, String description, Map<String, Map<String, Object>> properties,
			List<String> required) {}

	private static final int MAX_RESULT_CHARS = 30_000;
	private static final int DEFAULT_LIMIT = 50;

	private final AIAssistantPlugin plugin;
	private final Map<String, Function<JsonObject, String>> handlers = new LinkedHashMap<>();
	private final List<ToolSpec> specs = new ArrayList<>();
	private TaskMonitor monitor = TaskMonitor.DUMMY;

	AITools(AIAssistantPlugin plugin) {
		this.plugin = plugin;

		add("get_program_info",
			"Basic facts about the open program: name, format, processor, compiler, image base, " +
				"memory blocks and counts of functions/symbols.",
			Map.of(), List.of(), a -> programInfo());
		add("get_current_location",
			"Where the user's cursor is right now (address, containing function, selection). " +
				"Use this when the user says 'here', 'this function', 'this code' and so on.",
			Map.of(), List.of(), a -> currentLocation());
		add("search_functions",
			"Find functions whose name contains the query (case-insensitive). Returns name, " +
				"entry address and signature. Use an empty query to list functions.",
			Map.of("query", str("Part of the function name, e.g. 'crypt' or 'recv'"),
				"limit", num("Maximum results (default 50)")),
			List.of("query"), a -> searchFunctions(s(a, "query"), limit(a)));
		add("search_strings",
			"Find defined strings in the program that contain the query (case-insensitive). " +
				"Returns the address and the string. Useful for finding error messages, URLs, " +
				"file names, registry keys, UI text, etc.",
			Map.of("query", str("Text to look for inside strings"),
				"limit", num("Maximum results (default 50)")),
			List.of("query"), a -> searchStrings(s(a, "query"), limit(a)));
		add("search_symbols",
			"Find any symbol (labels, functions, globals, imports, classes, namespaces) whose " +
				"name contains the query (case-insensitive).",
			Map.of("query", str("Part of the symbol name"),
				"limit", num("Maximum results (default 50)")),
			List.of("query"), a -> searchSymbols(s(a, "query"), limit(a)));
		add("list_imports",
			"List imported (external) functions and symbols with their library, optionally " +
				"filtered by a query.",
			Map.of("query", str("Optional filter on the import name"),
				"limit", num("Maximum results (default 200)")),
			List.of(), a -> listImports(s(a, "query"), limit(a, 200)));
		add("list_entry_points",
			"List the program's entry points and exported symbols.",
			Map.of("limit", num("Maximum results (default 100)")),
			List.of(), a -> listEntryPoints(limit(a, 100)));
		add("get_references_to",
			"Find everything that references a function, label or address (cross references / " +
				"xrefs). Shows the referencing address, reference type and containing function. " +
				"This answers 'who calls X', 'who uses this string', 'where is this used'.",
			Map.of("target", str("Function name, symbol name or address (e.g. 0x401000)"),
				"limit", num("Maximum results (default 100)")),
			List.of("target"), a -> referencesTo(s(a, "target"), limit(a, 100)));
		add("get_callers",
			"List the functions that call the given function.",
			Map.of("target", str("Function name or an address inside it")),
			List.of("target"), a -> callers(s(a, "target")));
		add("get_callees",
			"List the functions called by the given function.",
			Map.of("target", str("Function name or an address inside it")),
			List.of("target"), a -> callees(s(a, "target")));
		add("decompile_function",
			"Decompile a function to C pseudo-code.",
			Map.of("target", str("Function name or an address inside it")),
			List.of("target"), a -> decompile(s(a, "target")));
		add("disassemble",
			"Show the listing (instructions and data) starting at an address or function.",
			Map.of("target", str("Function name, symbol or address"),
				"count", num("Number of code units to show (default 40, max 400)")),
			List.of("target"), a -> disassemble(s(a, "target"), limit(a, 40)));
		add("go_to",
			"Move the user's Ghidra listing to an address or function so they can see it. Use " +
				"this when you have found the place the user asked about.",
			Map.of("target", str("Function name, symbol or address")),
			List.of("target"), a -> goTo(s(a, "target")));
	}

	List<ToolSpec> getSpecs() {
		return specs;
	}

	void setMonitor(TaskMonitor monitor) {
		this.monitor = monitor == null ? TaskMonitor.DUMMY : monitor;
	}

	/**
	 * Runs a tool and returns its textual result. Errors are returned as text so the model can
	 * recover (for example by searching for the right name).
	 */
	String execute(String name, JsonObject args) {
		Function<JsonObject, String> handler = handlers.get(name);
		if (handler == null) {
			return "Error: unknown tool '" + name + "'";
		}
		if (plugin.getProgram() == null) {
			return "Error: no program is open in Ghidra";
		}
		try {
			String result = handler.apply(args == null ? new JsonObject() : args);
			if (result.length() > MAX_RESULT_CHARS) {
				result = result.substring(0, MAX_RESULT_CHARS) + "\n... [truncated]";
			}
			return result;
		}
		catch (Exception e) {
			return "Error: " + e.getMessage();
		}
	}

	// ---------------------------------------------------------------------------------------
	// tool implementations
	// ---------------------------------------------------------------------------------------

	private String programInfo() {
		Program p = plugin.getProgram();
		StringBuilder sb = new StringBuilder();
		sb.append("Name: ").append(p.getName()).append('\n');
		sb.append("Path: ").append(p.getExecutablePath()).append('\n');
		sb.append("Format: ").append(p.getExecutableFormat()).append('\n');
		sb.append("Language: ").append(p.getLanguageID()).append('\n');
		sb.append("Compiler: ").append(p.getCompilerSpec().getCompilerSpecID()).append('\n');
		sb.append("Image base: ").append(p.getImageBase()).append('\n');
		sb.append("MD5: ").append(p.getExecutableMD5()).append('\n');
		sb.append("Functions: ").append(p.getFunctionManager().getFunctionCount()).append('\n');
		sb.append("Symbols: ").append(p.getSymbolTable().getNumSymbols()).append('\n');
		sb.append("Memory blocks:\n");
		for (MemoryBlock b : p.getMemory().getBlocks()) {
			sb.append("  ").append(b.getName()).append(' ').append(b.getStart()).append('-')
					.append(b.getEnd()).append(' ').append(b.isRead() ? 'r' : '-')
					.append(b.isWrite() ? 'w' : '-').append(b.isExecute() ? 'x' : '-')
					.append('\n');
		}
		return sb.toString();
	}

	private String currentLocation() {
		Address addr = plugin.getCurrentAddress();
		if (addr == null) {
			return "No current location";
		}
		StringBuilder sb = new StringBuilder("Address: " + addr + "\n");
		ghidra.program.model.listing.Function f = plugin.getProgram().getFunctionManager()
				.getFunctionContaining(addr);
		sb.append("Function: ").append(f == null ? "(none)" : describe(f)).append('\n');
		CodeUnit cu = plugin.getProgram().getListing().getCodeUnitContaining(addr);
		if (cu != null) {
			sb.append("Code unit: ").append(cu).append('\n');
		}
		String selection = plugin.getSelectionDescription();
		if (selection != null) {
			sb.append("Selection: ").append(selection).append('\n');
		}
		return sb.toString();
	}

	private String searchFunctions(String query, int limit) {
		String q = query.toLowerCase();
		StringBuilder sb = new StringBuilder();
		int n = 0;
		FunctionManager fm = plugin.getProgram().getFunctionManager();
		for (ghidra.program.model.listing.Function f : fm.getFunctions(true)) {
			if (monitor.isCancelled() || n >= limit) {
				break;
			}
			if (f.getName(true).toLowerCase().contains(q)) {
				sb.append(describe(f)).append('\n');
				n++;
			}
		}
		return n == 0 ? "No functions match '" + query + "'" : sb.toString();
	}

	private String searchStrings(String query, int limit) {
		String q = query.toLowerCase();
		StringBuilder sb = new StringBuilder();
		int n = 0;
		for (Data data : DefinedStringIterator.forProgram(plugin.getProgram())) {
			if (monitor.isCancelled() || n >= limit) {
				break;
			}
			String value = StringDataInstance.getStringDataInstance(data).getStringValue();
			if (value != null && value.toLowerCase().contains(q)) {
				sb.append(data.getAddress()).append(": \"").append(clip(value, 200)).append("\"\n");
				n++;
			}
		}
		return n == 0 ? "No strings contain '" + query + "'" : sb.toString();
	}

	private String searchSymbols(String query, int limit) {
		SymbolIterator it =
			plugin.getProgram().getSymbolTable().getSymbolIterator("*" + query + "*", false);
		StringBuilder sb = new StringBuilder();
		int n = 0;
		while (it.hasNext() && n < limit && !monitor.isCancelled()) {
			Symbol s = it.next();
			sb.append(s.getName(true)).append(" [").append(s.getSymbolType()).append("] @ ")
					.append(s.getAddress()).append('\n');
			n++;
		}
		return n == 0 ? "No symbols match '" + query + "'" : sb.toString();
	}

	private String listImports(String query, int limit) {
		String q = query.toLowerCase();
		StringBuilder sb = new StringBuilder();
		int n = 0;
		for (Symbol s : plugin.getProgram().getSymbolTable().getExternalSymbols()) {
			if (n >= limit || monitor.isCancelled()) {
				break;
			}
			if (!q.isEmpty() && !s.getName(true).toLowerCase().contains(q)) {
				continue;
			}
			sb.append(s.getParentNamespace().getName()).append("::").append(s.getName())
					.append(" [").append(s.getSymbolType()).append("]\n");
			n++;
		}
		return n == 0 ? "No imports found" : sb.toString();
	}

	private String listEntryPoints(int limit) {
		Program p = plugin.getProgram();
		StringBuilder sb = new StringBuilder();
		int n = 0;
		var it = p.getSymbolTable().getExternalEntryPointIterator();
		while (it.hasNext() && n < limit) {
			Address a = it.next();
			Symbol s = p.getSymbolTable().getPrimarySymbol(a);
			sb.append(a).append(' ').append(s == null ? "" : s.getName(true)).append('\n');
			n++;
		}
		return n == 0 ? "No entry points" : sb.toString();
	}

	private String referencesTo(String target, int limit) {
		Program p = plugin.getProgram();
		Address addr = resolveAddress(target);
		StringBuilder sb = new StringBuilder("References to " + target + " (" + addr + "):\n");
		int n = 0;
		for (Reference ref : p.getReferenceManager().getReferencesTo(addr)) {
			if (n >= limit || monitor.isCancelled()) {
				sb.append("... more references not shown\n");
				break;
			}
			Address from = ref.getFromAddress();
			ghidra.program.model.listing.Function f =
				p.getFunctionManager().getFunctionContaining(from);
			CodeUnit cu = p.getListing().getCodeUnitAt(from);
			sb.append(from).append(" [").append(ref.getReferenceType()).append("] in ")
					.append(f == null ? "(no function)" : f.getName(true))
					.append(cu == null ? "" : "  : " + cu).append('\n');
			n++;
		}
		return n == 0 ? "No references to " + target + " (" + addr + ")" : sb.toString();
	}

	private String callers(String target) {
		ghidra.program.model.listing.Function f = resolveFunction(target);
		Set<ghidra.program.model.listing.Function> set = f.getCallingFunctions(monitor);
		return listFunctions("Functions that call " + f.getName(true), set);
	}

	private String callees(String target) {
		ghidra.program.model.listing.Function f = resolveFunction(target);
		Set<ghidra.program.model.listing.Function> set = f.getCalledFunctions(monitor);
		return listFunctions("Functions called by " + f.getName(true), set);
	}

	private String listFunctions(String title, Set<ghidra.program.model.listing.Function> set) {
		if (set.isEmpty()) {
			return title + ": none";
		}
		StringBuilder sb = new StringBuilder(title + ":\n");
		set.stream()
				.sorted(Comparator.comparing(ghidra.program.model.listing.Function::getEntryPoint))
				.forEach(f -> sb.append(describe(f)).append('\n'));
		return sb.toString();
	}

	private String decompile(String target) {
		ghidra.program.model.listing.Function f = resolveFunction(target);
		if (f.isExternal()) {
			return f.getName(true) + " is an external (imported) function; it has no body. " +
				"Signature: " + f.getPrototypeString(false, false);
		}
		String c = plugin.decompile(f, monitor);
		return c == null ? "Decompilation of " + f.getName(true) + " failed"
				: "// " + f.getName(true) + " @ " + f.getEntryPoint() + "\n" + c;
	}

	private String disassemble(String target, int count) {
		Program p = plugin.getProgram();
		Address addr = resolveAddress(target);
		count = Math.min(count, 400);
		StringBuilder sb = new StringBuilder();
		// a function target shows just that function's body; an address shows what follows it
		ghidra.program.model.listing.Function f = p.getFunctionManager().getFunctionAt(addr);
		CodeUnitIterator it = f != null && !f.isExternal()
				? p.getListing().getCodeUnits(f.getBody(), true)
				: p.getListing().getCodeUnits(addr, true);
		int n = 0;
		while (it.hasNext() && n < count) {
			CodeUnit cu = it.next();
			String label = cu.getLabel();
			if (label != null) {
				sb.append(label).append(":\n");
			}
			sb.append("  ").append(cu.getAddress()).append("  ").append(cu);
			String eol = cu.getComment(CommentType.EOL);
			if (eol != null) {
				sb.append("  ; ").append(eol.replace('\n', ' '));
			}
			sb.append('\n');
			n++;
		}
		return sb.toString();
	}

	private String goTo(String target) {
		Address addr = resolveAddress(target);
		GoToService service = plugin.getTool().getService(GoToService.class);
		if (service == null) {
			return "Navigation is not available in this tool";
		}
		boolean[] ok = { false };
		Swing.runNow(() -> ok[0] = service.goTo(addr, plugin.getProgram()));
		return ok[0] ? "Moved the listing to " + addr : "Could not navigate to " + addr;
	}

	// ---------------------------------------------------------------------------------------
	// helpers
	// ---------------------------------------------------------------------------------------

	/**
	 * Resolves a function name, symbol name or address string to an address.
	 */
	Address resolveAddress(String target) {
		Program p = plugin.getProgram();
		String t = target.strip();
		if (t.isEmpty()) {
			throw new IllegalArgumentException("empty target");
		}
		// "0x..." or "space:offset" is always an address; a bare word like "dead" may be a name
		boolean explicitAddress = t.startsWith("0x") || t.startsWith("0X") || t.contains(":") &&
			!t.contains("::");
		Address addr = explicitAddress ? parseAddress(p, t) : null;
		if (addr != null) {
			return addr;
		}
		ghidra.program.model.listing.Function f = findFunctionByName(p, t);
		if (f != null) {
			return f.getEntryPoint();
		}
		for (Symbol s : p.getSymbolTable().getSymbols(t)) {
			return s.getAddress();
		}
		SymbolIterator it = p.getSymbolTable().getSymbolIterator(t, false);
		if (it.hasNext()) {
			return it.next().getAddress();
		}
		addr = parseAddress(p, t);
		if (addr != null) {
			return addr;
		}
		throw new IllegalArgumentException("'" + target + "' is not a known function, " +
			"symbol or address. Try search_functions or search_symbols first.");
	}

	/**
	 * Resolves a function name or any address inside a function.
	 */
	ghidra.program.model.listing.Function resolveFunction(String target) {
		Program p = plugin.getProgram();
		ghidra.program.model.listing.Function f = findFunctionByName(p, target.strip());
		if (f != null) {
			return f;
		}
		Address addr = resolveAddress(target);
		f = p.getFunctionManager().getFunctionContaining(addr);
		if (f == null) {
			f = p.getFunctionManager().getFunctionAt(addr);
		}
		if (f == null) {
			throw new IllegalArgumentException("No function at or containing " + addr);
		}
		return f;
	}

	private static ghidra.program.model.listing.Function findFunctionByName(Program p,
			String name) {
		List<ghidra.program.model.listing.Function> global =
			p.getListing().getGlobalFunctions(name);
		if (!global.isEmpty()) {
			return global.get(0);
		}
		for (Symbol s : p.getSymbolTable().getSymbols(name)) {
			if (s.getSymbolType() == SymbolType.FUNCTION) {
				return (ghidra.program.model.listing.Function) s.getObject();
			}
		}
		for (ghidra.program.model.listing.Function f : p.getFunctionManager()
				.getFunctions(true)) {
			if (f.getName(true).equalsIgnoreCase(name) || f.getName().equalsIgnoreCase(name)) {
				return f;
			}
		}
		for (ghidra.program.model.listing.Function f : p.getFunctionManager()
				.getExternalFunctions()) {
			if (f.getName().equalsIgnoreCase(name)) {
				return f;
			}
		}
		return null;
	}

	private static Address parseAddress(Program p, String s) {
		String t = s.replaceFirst("^(?i)0x", "");
		try {
			return p.getAddressFactory().getAddress(t);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static String describe(ghidra.program.model.listing.Function f) {
		return f.getName(true) + " @ " + f.getEntryPoint() + "  " +
			f.getPrototypeString(false, false);
	}

	private static String clip(String s, int max) {
		s = s.replace("\n", "\\n").replace("\r", "\\r");
		return s.length() <= max ? s : s.substring(0, max) + "...";
	}

	private void add(String name, String description, Map<String, Map<String, Object>> props,
			List<String> required, Function<JsonObject, String> handler) {
		specs.add(new ToolSpec(name, description, props, required));
		handlers.put(name, handler);
	}

	private static Map<String, Object> str(String description) {
		return Map.of("type", "string", "description", description);
	}

	private static Map<String, Object> num(String description) {
		return Map.of("type", "integer", "description", description);
	}

	private static String s(JsonObject a, String key) {
		return a.has(key) && !a.get(key).isJsonNull() ? a.get(key).getAsString() : "";
	}

	private static int limit(JsonObject a) {
		return limit(a, DEFAULT_LIMIT);
	}

	private static int limit(JsonObject a, int def) {
		for (String key : List.of("limit", "count")) {
			if (a.has(key) && !a.get(key).isJsonNull()) {
				try {
					return Math.max(1, Math.min(1000, a.get(key).getAsInt()));
				}
				catch (RuntimeException e) {
					// fall through to the default
				}
			}
		}
		return def;
	}
}
