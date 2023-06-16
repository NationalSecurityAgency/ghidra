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
package ghidra.app.util.bin.format.macho.commands;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;

/**
 * Represents a LC_DYLD_EXPORTS_TRIE command 
 */
public class DyldExportsTrieCommand extends LinkEditDataCommand {

	private ExportTrie exportTrie;
	
	/**
	 * Creates and parses a new {@link DyldExportsTrieCommand}
	 * 
	 * @param loadCommandReader A {@link BinaryReader reader} that points to the start of the load
	 *   command
	 * @param dataReader A {@link BinaryReader reader} that can read the data that the load command
	 *   references.  Note that this might be in a different underlying provider.
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	DyldExportsTrieCommand(BinaryReader loadCommandReader, BinaryReader dataReader)
			throws IOException {
		super(loadCommandReader, dataReader);
		exportTrie = dataoff > 0 && datasize > 0 ? new ExportTrie(dataReader) : new ExportTrie();
	}
	
	/**
	 * Gets the {@link ExportTrie}
	 * 
	 * @return The {@link ExportTrie}
	 */
	public ExportTrie getExportTrie() {
		return exportTrie;
	}
}
