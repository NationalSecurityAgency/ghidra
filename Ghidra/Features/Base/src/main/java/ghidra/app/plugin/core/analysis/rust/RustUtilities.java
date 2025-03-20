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
package ghidra.app.plugin.core.analysis.rust;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.framework.Application;
import ghidra.framework.store.LockException;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.bytesearch.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlParseException;

/**
 * Rust utility functions
 */
public class RustUtilities {

	/**
	 * Checks if a given {@link MemoryBlock} contains a Rust signature
	 * <p>
	 * This may be used by loaders to determine if a program was compiled with rust.
	 * If the program is determined to be rust, then the compiler property is set to
	 * {@link RustConstants#RUST_COMPILER}.
	 *
	 * @param program The {@link Program}
	 * @param block The {@link MemoryBlock} to scan for Rust signatures
	 * @param monitor The monitor
	 * @return True if the given {@link MemoryBlock} is not null and contains a Rust signature; 
	 *   otherwise, false
	 * @throws IOException if there was an IO-related error
	 * @throws CancelledException if the user cancelled the operation
	 */
	public static boolean isRust(Program program, MemoryBlock block, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (block == null) {
			return false;
		}

		// Use a MemoryBytePatternSearch for more efficient byte searching over a list of potential
		// byte signatures. The below action sets our supplied boolean to true on a match, which we
		// can later query and use as a return value for this method.
		GenericMatchAction<AtomicBoolean> action =
			new GenericMatchAction<AtomicBoolean>(new AtomicBoolean()) {
			@Override
			public void apply(Program prog, Address addr, Match match) {
				getMatchValue().set(true);
			}
		};
		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Rust signatures");
		for (byte[] sig : RustConstants.RUST_SIGNATURES) {
			searcher.addPattern(new GenericByteSequencePattern<AtomicBoolean>(sig, action));
		}

		searcher.search(program, new AddressSet(block.getAddressRange()), monitor);

		return action.getMatchValue().get();
	}

	/**
	 * Returns true if the given program has earlier been tagged as having a Rust compiler by
	 * the loader.
	 *  
	 * @param program {@link Program}
	 * @return boolean true if program's compiler property includes rust
	 */
	public static boolean isRustProgram(Program program) {
		String name = program.getCompiler();
		return name != null && name.contains(RustConstants.RUST_COMPILER);
	}

	public static int addExtensions(Program program, TaskMonitor monitor, String subPath)
			throws IOException {
		Processor processor = program.getLanguageCompilerSpecPair().getLanguage().getProcessor();
		ResourceFile module = Application.getModuleDataSubDirectory(processor.toString(),
			RustConstants.RUST_EXTENSIONS_PATH + subPath);

		int extensionCount = 0;

		ResourceFile[] files = module.listFiles();
		if (files != null) {
			for (ResourceFile file : files) {
				InputStream stream = file.getInputStream();
				byte[] bytes = stream.readAllBytes();
				String xml = new String(bytes);

				try {
					SpecExtension extension = new SpecExtension(program);
					extension.addReplaceCompilerSpecExtension(xml, monitor);
					extensionCount++;
				}
				catch (SleighException | SAXException | XmlParseException | LockException e) {
					Msg.error(RustUtilities.class,
						"Failed to load Rust cspec extension: " + file.getAbsolutePath(), e);
				}
			}
		}

		return extensionCount;
	}
}
