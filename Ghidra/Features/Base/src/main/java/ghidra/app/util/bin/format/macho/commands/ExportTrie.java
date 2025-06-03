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

import static ghidra.app.util.bin.format.macho.commands.DyldInfoCommandConstants.*;

import java.io.IOException;
import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.data.LEB128;

/**
 * Mach-O export trie
 * 
 * @see <a href="https://github.com/qyang-nj/llios/blob/main/exported_symbol/README.md">Exported Symbol</a>
 * @see <a href="https://github.com/opensource-apple/dyld/blob/master/launch-cache/MachOTrie.hpp">dyld/launch-cache/MachOTrie.hpp</a> 
 */
public class ExportTrie {
	
	private BinaryReader reader;
	private long base;

	private List<ExportEntry> exports;
	private List<Long> ulebOffsets;
	private List<Long> stringOffsets;
	
	/**
	 * Creates an empty {@link ExportTrie}.  This is useful for export trie load commands that are
	 * defined but do not point to any data. 
	 */
	public ExportTrie() {
		this.exports = new ArrayList<>();
		this.ulebOffsets = new ArrayList<>();
		this.stringOffsets = new ArrayList<>();
	}

	/**
	 * Creates and parses a new {@link ExportTrie}
	 * 
	 * @param reader A {@link BinaryReader reader} positioned at the start of the export trie
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	public ExportTrie(BinaryReader reader) throws IOException {
		this();
		this.reader = reader;
		this.base = reader.getPointerIndex();
		
		parseTrie();
	}
	
	/**
	 * Gets the {@link List} of {@link ExportEntry exports}
	 * 
	 * @return The {@link List} of {@link ExportEntry exports}
	 */
	public List<ExportEntry> getExports() {
		return exports;
	}
	
	/**
	 * Gets the {@link List} of {@link ExportEntry exports}
	 * 
	 * @param filter A filter on the returned {@link List}
	 * @return The {@link List} of {@link ExportEntry exports}
	 */
	public List<ExportEntry> getExports(Predicate<ExportEntry> filter) {
		return exports.stream().filter(filter).collect(Collectors.toList());
	}

	/**
	 * Parses the export trie
	 * 
	 * @throws IOException if there was an IO-related error
	 */
	private void parseTrie() throws IOException {
		LinkedList<Node> remainingNodes = parseNode("", 0);
		while(!remainingNodes.isEmpty()) {
			Node parent = remainingNodes.removeFirst();
			LinkedList<Node> children = parseNode(parent.name, parent.offset);
			for (Node child : children) {
				remainingNodes.add(new Node(parent.name + child.name, child.offset));
			}
		}
	}
	
	/**
	 * Parses a node of the export trie
	 * 
	 * @param name The node edge (symbol name substring)
	 * @param offset An offset from the data base where the node starts
	 * @return A {@link LinkedList list} of child {@link Node nodes}
	 * @throws IOException if there was an IO-related error
	 */
	private LinkedList<Node> parseNode(String name, int offset) throws IOException {
		LinkedList<Node> children = new LinkedList<>();
		reader.setPointerIndex(base + offset);
		ulebOffsets.add(reader.getPointerIndex() - base);
		int terminalSize = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		long childrenIndex = reader.getPointerIndex() + terminalSize;
		if (terminalSize != 0) {
			ulebOffsets.add(reader.getPointerIndex() - base);
			long flags = reader.readNext(LEB128::unsigned);
			long address = 0;
			long other = 0;
			String importName = null;
			if ((flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0) {
				ulebOffsets.add(reader.getPointerIndex() - base);
				other = reader.readNext(LEB128::unsigned); // dylib ordinal
				stringOffsets.add(reader.getPointerIndex() - base);
				importName = reader.readNextAsciiString();
			}
			else {
				ulebOffsets.add(reader.getPointerIndex() - base);
				address = reader.readNext(LEB128::unsigned);
				if ((flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0) {
					ulebOffsets.add(reader.getPointerIndex() - base);
					other = reader.readNext(LEB128::unsigned);
				}
			}
			ExportEntry export = new ExportEntry(name, address, flags, other, importName);
			exports.add(export);
		}
		reader.setPointerIndex(childrenIndex);
		ulebOffsets.add(reader.getPointerIndex() - base);
		int numChildren = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
		for (int i = 0; i < numChildren; i++) {
			stringOffsets.add(reader.getPointerIndex() - base);
			String childName = reader.readNextAsciiString();
			ulebOffsets.add(reader.getPointerIndex() - base);
			int childOffset = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
			children.add(new Node(childName, childOffset));
		}
		return children;
	}
	
	/**
	 * Creates a new {@link ExportEntry}
	 * 
	 * @param name The export name
	 * @param address The export address
	 * @param flags The export flags
	 * @param other The export "other" info
	 * @param importName The export import name (could be null if not a re-export)
	 */
	public record ExportEntry(String name, long address, long flags, long other,
			String importName) {

		/**
		 * Check to see if the export is a "re-export"
		 * 
		 * @return True if re-export; otherwise, false
		 */
		public boolean isReExport() {
			return (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0;
		}

		@Override
		public String toString() {
			return String.format("%s addr: 0x%x, flags: 0x%x, other: 0x%x, importName: %s", name,
				address, flags, other, importName != null ? importName : "<null>");
		}
	}
	
	/**
	 * {@return ULEB128 offsets from the start of the export trie}
	 */
	public List<Long> getUlebOffsets() {
		return ulebOffsets;
	}

	/**
	 * {@return String offsets from the start of the export trie}
	 */
	public List<Long> getStringOffsets() {
		return stringOffsets;
	}

	/**
	 * A trie node
	 */
	private record Node(String name, int offset) {

		@Override
		public String toString() {
			return String.format("%s, 0x%x", name, offset);
		}
	}
}
