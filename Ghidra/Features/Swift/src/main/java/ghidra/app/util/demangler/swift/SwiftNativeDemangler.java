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

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A class used to launch the Swift native demangler.
 * <p>
 * The Swift native demangler binary comes in 2 forms, and can thus be invoked in 2 ways:
 * <ul>
 *   <li>{@code ./swift demangle args}</li>
 *   <li>{@code ./swift-demangle args}</li>
 * </ul>
 * 
 * The latter is how it is done in the Windows version of Swift.  We will refer to this version
 * as the "standalone demangler binary".
 */
public class SwiftNativeDemangler {

	private String nativeDemanglerPath;
	private boolean standaloneDemanglerBinary;
	
	/**
	 * The output of the native Swift demangler
	 * 
	 * @param demangled The demangled string
	 * @param tree The lines of the demangled expanded tree
	 */
	public record SwiftNativeDemangledOutput(String demangled, List<String> tree) {
		@Override
		public String toString() {
			return "%s\n%s".formatted(demangled != null ? demangled : "<NULL>",
				tree.stream().collect(Collectors.joining("\n")));
		}
	}

	/**
	 * Creates a new {@link SwiftNativeDemangler}
	 * 
	 * @param swiftDir The Swift directory
	 * @throws IOException if there was a problem finding or running the Swift native demangler
	 */
	public SwiftNativeDemangler(File swiftDir) throws IOException {
		List<String> demanglerNames = List.of("swift-demangle", "swift");
		IOException ioe = null;
		for (String demanglerName : demanglerNames) {
			nativeDemanglerPath = demanglerName;
			if (swiftDir != null) {
				nativeDemanglerPath = swiftDir + File.separator + nativeDemanglerPath;
			}
			try {
				int exitCode =
					new ProcessBuilder(List.of(nativeDemanglerPath, "--version")).start()
							.waitFor();
				if (exitCode == 0) {
					ioe = null;
					standaloneDemanglerBinary =
						new File(nativeDemanglerPath).getName().contains("-demangle");
					break;
				}
				ioe = new IOException("Native Swift demangler exited with code: " + exitCode);
			}
			catch (IOException e) {
				ioe = e;
			}
			catch (InterruptedException e) {
				ioe = new IOException(e);
			}
		}
		if (ioe != null) {
			throw ioe;
		}
	}

	/**
	 * Uses the Swift executable to demangle the given mangled string
	 * 
	 * @param mangled The mangled string to demangle
	 * @return The {@link SwiftNativeDemangledOutput}
	 * @throws IOException If there was an IO-related issue
	 * @see SwiftDemangledTree
	 */
	public SwiftNativeDemangledOutput demangle(String mangled) throws IOException {
		List<String> demanglerArgs = new ArrayList<>();
		demanglerArgs.add("--compact"); // Compact mode (only emit the demangled names)
		demanglerArgs.add("--expand");  // Expand mode (show node structure of the demangling)
		try (BufferedReader reader = demangle(mangled, demanglerArgs)) {
			String demangled = null;
			List<String> treeLines = new ArrayList<>();
			String line = reader.readLine().trim();
			if (!line.startsWith("Demangling for")) {
				throw new IOException("Unexpected output: " + line);
			}
			while ((line = reader.readLine()) != null) {
				if (line.startsWith("<<NULL>>")) { // Not a demangleable string
					break;
				}
				if (line.isBlank()) {
					continue;
				}
				if (treeLines.isEmpty() && !line.trim().startsWith("kind")) {
					// This case is mainly for when the mangled string has newline characters in it,
					// which are printed in the first "Demangling for..." line. We want to skip
					// those and get to the tree.
					continue;
				}
				if (!treeLines.isEmpty() && !line.startsWith(" ")) {
					// This case should grab the last line after the tree, which is the full 
					// demangled string
					demangled = line;
					break;
				}
				treeLines.add(line);
			}
			return new SwiftNativeDemangledOutput(demangled, treeLines);
		}
	}

	/**
	 * Runs the Swift demangler to demangled the given mangled string with the given demangle 
	 * options
	 * 
	 * @param mangled The mangled string to demangle
	 * @param options Additional demangle options
	 * @return A {@link BufferedReader} used to read the output of the executed command
	 * @throws IOException If there was an IO-related issue
	 */
	private BufferedReader demangle(String mangled, List<String> options) throws IOException {
		List<String> command = new ArrayList<>();
		command.add(nativeDemanglerPath);
		if (!standaloneDemanglerBinary) {
			command.add("demangle");
		}
		command.addAll(options);
		command.add(mangled);
		Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
		return new BufferedReader(new InputStreamReader(p.getInputStream()));
	}
}
