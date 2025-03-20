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

import org.xml.sax.SAXException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.framework.Application;
import ghidra.framework.store.LockException;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
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
	 * @param block The {@link MemoryBlock} to scan for Rust signatures
	 * @return True if the given {@link MemoryBlock} is not null and contains a Rust signature; 
	 *   otherwise, false
	 * @throws IOException if there was an IO-related error
	 */
	public static boolean isRust(MemoryBlock block) throws IOException {
		if (block == null) {
			return false;
		}
		byte[] bytes = block.getData().readAllBytes();
		if (containsBytes(bytes, RustConstants.RUST_SIGNATURE_1)) {
			return true;
		}
		if (containsBytes(bytes, RustConstants.RUST_SIGNATURE_2)) {
			return true;
		}
		if (containsBytes(bytes, RustConstants.RUST_SIGNATURE_3)) {
			return true;
		}
		return false;
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

	private static boolean containsBytes(byte[] data, byte[] bytes) {
		for (int i = 0; i < data.length - bytes.length; i++) {
			boolean isMatch = true;
			for (int j = 0; j < bytes.length; j++) {
				if (Byte.compare(data[i + j], bytes[j]) != 0) {
					isMatch = false;
					break;
				}
			}

			if (isMatch) {
				return true;
			}
		}

		return false;
	}
}
