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
	 * Checks if a given {@link Program} was written in Rust
	 * 
	 * @param program The {@link Program} to check
	 * @param blockName The name of the {@link MemoryBlock} to scan for Rust signatures
	 * @return True if the given {@link Program} was written in Rust; otherwise, false
	 * @throws IOException if there was an IO-related error
	 */
	public static boolean isRust(Program program, String blockName) throws IOException {
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.getName().equals(blockName)) {
				byte[] bytes = block.getData().readAllBytes();
				if (containsBytes(bytes, RustConstants.RUST_SIGNATURE_1)) {
					return true;
				}
				if (containsBytes(bytes, RustConstants.RUST_SIGNATURE_2)) {
					return true;
				}
			}
		}
		return false;
	}

	public static int addExtensions(Program program, TaskMonitor monitor, String subPath)
			throws IOException {
		var processor = program.getLanguageCompilerSpecPair().getLanguage().getProcessor();
		ResourceFile module = Application.getModuleDataSubDirectory(processor.toString(),
			RustConstants.RUST_EXTENSIONS_PATH + subPath);

		int extensionCount = 0;

		ResourceFile[] files = module.listFiles();
		for (ResourceFile file : files) {
			InputStream stream = file.getInputStream();
			byte[] bytes = stream.readAllBytes();
			String xml = new String(bytes);

			try {
				SpecExtension extension = new SpecExtension(program);
				extension.addReplaceCompilerSpecExtension(xml, monitor);
				extensionCount += 1;
			}
			catch (SleighException | SAXException | XmlParseException | LockException e) {
				Msg.error(program, "Failed to load load cspec extensions");
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
