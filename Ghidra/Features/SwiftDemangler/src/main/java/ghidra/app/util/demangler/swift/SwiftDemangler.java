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

	private Map<String, SwiftNode> cache;
	private SwiftTypeMetadata typeMetadata;
	private SwiftNativeDemangler nativeDemangler;

	/**
	 * Creates a new {@link SwiftDemangler} that is not associated with any {@link Program}.
	 * Call {@link #initialize(Program)} to associate it with a program, which will enable access
	 * to the Swift type metadata.
	 */
	public SwiftDemangler() {
		super();
		try {
			initialize(null);
		}
		catch (IOException e) {
			// should not happen when initializing with null
		}
	}

	/**
	 * Creates a new {@link SwiftDemangler} that is associated with the given {@link Program}
	 * 
	 * @param program The {@link Program} to demangle
	 * @throws IOException if there was a problem parsing the Swift type metadata
	 */
	public SwiftDemangler(Program program) throws IOException {
		super();
		initialize(program);
	}

	@Override
	public boolean canDemangle(Program program) {
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

	public void initialize(Program program) throws IOException {
		cache = new HashMap<>();
		nativeDemangler = null;
		try {
			if (program != null) {
				program.setPreferredRootNamespaceCategoryPath(
					SwiftDataTypeUtils.SWIFT_CATEGORY.getPath());
				typeMetadata = new SwiftTypeMetadata(program, TaskMonitor.DUMMY, new MessageLog());
			}
		}
		catch (CancelledException e) {
			return;
		}
	}

	@Override
	public DemangledObject demangle(String mangled, DemanglerOptions op) throws DemangledException {
		SwiftDemanglerOptions options = getSwiftDemanglerOptions(op);
		Demangled demangled = getDemangled(mangled, options);
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
	 * Get a new {@link Demangled} by demangling the given mangled string
	 * 
	 * @param mangled The mangled string
	 * @param op The options (could be null)
	 * @return A new {@link Demangled}
	 * @throws DemangledException if there was an issue demangling
	 */
	public Demangled getDemangled(String mangled, SwiftDemanglerOptions op)
			throws DemangledException {
		if (!isSwiftMangledSymbol(mangled)) {
			return null;
		}

		SwiftDemanglerOptions options = getSwiftDemanglerOptions(op);
		setSwiftNativeDemangler(options);

		SwiftNode root = cache.containsKey(mangled) ? cache.get(mangled)
				: new SwiftDemangledTree(nativeDemangler, mangled).getRoot();
		cache.put(mangled, root);
		if (root == null) {
			return null;
		}

		Demangled demangled = root.demangle(this);
		if (root.walkAndTest(node -> node.childWasSkipped())) {
			demangled.setName(options.getIncompletePrefix() + demangled.getName());
		}

		return demangled;
	}

	/**
	 * Gets the {@link SwiftTypeMetadata}
	 * 
	 * @return The {@link SwiftTypeMetadata}, or null if it is not available
	 */
	public SwiftTypeMetadata getTypeMetadata() {
		return typeMetadata;
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

	/**
	 * Ensures that this demangler has access to a {@link SwiftNativeDemangler}
	 * 
	 * @param options The options
	 * @throws DemangledException if there was a problem getting the {@link SwiftNativeDemangler}
	 */
	private void setSwiftNativeDemangler(SwiftDemanglerOptions options) throws DemangledException {
		if (nativeDemangler == null) {
			try {
				nativeDemangler = new SwiftNativeDemangler(options.getSwiftDir());
			}
			catch (IOException e) {
				throw new DemangledException(e);
			}
		}
	}
}
