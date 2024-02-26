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
package ghidra.app.util.demangler.swift;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.swift.SwiftTypeMetadata;
import ghidra.app.util.bin.format.swift.SwiftUtils;
import ghidra.app.util.demangler.*;
import ghidra.app.util.demangler.swift.datatypes.SwiftDataTypeUtils;
import ghidra.app.util.demangler.swift.nodes.SwiftNode;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A demangler for mangled Swift symbols
 */
public class SwiftDemangler implements Demangler {

	private Program program;
	private SwiftTypeMetadata typeMetadata;
	private SwiftNativeDemangler nativeDemangler;
	private SwiftDemanglerOptions options;
	private Map<String, SwiftNode> cache;
	private DemangledException initException;

	@Override
	public boolean canDemangle(Program p) {
		this.program = p;
		return SwiftUtils.isSwift(program);
	}

	@Override
	public DemanglerOptions createDefaultOptions() {
		return new SwiftDemanglerOptions();
	}

	@Override
	public DemangledObject demangle(String mangled, boolean demangleOnlyKnownPatterns)
			throws DemangledException {
		return demangle(mangled);
	}

	/**
	 * Initializes class variables
	 * 
	 * @param opt The options
	 * @throws DemangledException If there was an issue with initialization
	 */
	private void init(DemanglerOptions opt) throws DemangledException {
		if (initException != null) {
			throw initException;
		}

		if (program != null && typeMetadata == null) {
			try {
				program.setPreferredRootNamespaceCategoryPath(
					SwiftDataTypeUtils.SWIFT_CATEGORY.getPath());
				typeMetadata = new SwiftTypeMetadata(program, TaskMonitor.DUMMY, new MessageLog());
			}
			catch (CancelledException e) {
				return;
			}
			catch (IOException e) {
				initException = new DemangledException(e);
				throw initException;
			}
		}

		if (opt != null) {
			options = getSwiftDemanglerOptions(opt);
		}
		
		if (nativeDemangler == null) {
			try {
				nativeDemangler = new SwiftNativeDemangler(options.getSwiftDir());
			}
			catch (IOException e) {
				throw new DemangledException(e);
			}
		}

		if (cache == null) {
			cache = new HashMap<>();
		}
	}

	/**
	 * Demangles the given mangled string
	 * 
	 * @param mangled The mangled string
	 * @param originalDemangled The demangled string produced by the native Swift demangler
	 * @param meta The {@link SwiftTypeMetadata}, or null if unavailable
	 * @return The {@link Demangled} object, or null if the mangled string is not a supported Swift
	 *   symbol
	 * @throws DemangledException if a problem occurred
	 */
	public Demangled demangle(String mangled, String originalDemangled, SwiftTypeMetadata meta)
			throws DemangledException {
		if (!isSwiftMangledSymbol(mangled)) {
			return null;
		}

		try {
			SwiftNode root;
			if (cache.containsKey(mangled)) {
				root = cache.get(mangled);
			}
			else {
				SwiftDemangledTree tree = new SwiftDemangledTree(nativeDemangler, mangled);
				root = tree.getRoot();
			}
			cache.put(mangled, root);
			if (root == null) {
				return null;
			}
			Demangled demangled = root.demangle(this, meta);
			if (root.walkAndTest(node -> node.childWasSkipped())) {
				demangled.setName(options.getIncompletePrefix() + demangled.getName());
			}
			return demangled;
		}
		catch (IOException e) {
			throw new DemangledException(e);
		}
	}

	@Override
	public DemangledObject demangle(String mangled, DemanglerOptions opt)
			throws DemangledException {

		init(opt);

		Demangled demangled = demangle(mangled, null, typeMetadata);
		if (demangled instanceof DemangledFunction func) {
			return func;
		}
		else if (demangled instanceof DemangledLabel label) {
			return label;
		}
		else if (demangled instanceof DemangledUnknown unknown) {
			return new DemangledLabel(mangled, unknown.getOriginalDemangled(),
				options.getUnsupportedPrefix() + unknown.getOriginalDemangled());
		}
		return null;
	}

	/**
	 * Clears the cache
	 */
	public void clearCache() {
		if (cache != null) {
			cache.clear();
		}
	}

	/**
	 * Checks to see whether the given symbol name is a mangled Swift symbol
	 * 
	 * @param symbolName The symbol name to check
	 * @return True if the given symbol name is a mangled Swift symbol; otherwise, false
	 */
	public boolean isSwiftMangledSymbol(String symbolName) {
		List<String> prefixes = List.of("$S", "$s", "_$S", "_$s", "_T");
		return prefixes.stream().anyMatch(prefix -> symbolName.startsWith(prefix));
	}

	/**
	 * Gets the {@link SwiftDemanglerOptions} from the given {@link DemanglerOptions}
	 * 
	 * @param opt The options
	 * @return The @link SwiftDemanglerOptions}
	 * @throws DemangledException If the given options are not {@link SwiftDemanglerOptions}
	 */
	public SwiftDemanglerOptions getSwiftDemanglerOptions(DemanglerOptions opt)
			throws DemangledException {
		if (!(opt instanceof SwiftDemanglerOptions)) {
			opt = createDefaultOptions();
		}
		return (SwiftDemanglerOptions) opt;
	}
}
