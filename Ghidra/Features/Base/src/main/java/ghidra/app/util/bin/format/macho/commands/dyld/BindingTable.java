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
package ghidra.app.util.bin.format.macho.commands.dyld;

import static ghidra.app.util.bin.format.macho.commands.DyldInfoCommandConstants.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.commands.DyldInfoCommandConstants;
import ghidra.program.model.data.LEB128;

/**
 * A Mach-O binding table
 */
public class BindingTable extends OpcodeTable {

	private List<Binding> bindings = new ArrayList<>();
	private List<Binding> threadedBindings;


	/**
	 * Creates an empty {@link BindingTable}
	 */
	public BindingTable() {
		super();
	}

	/**
	 * Creates and parses a new {@link BindingTable}
	 * 
	 * @param reader A {@link BinaryReader reader} positioned at the start of the binding table
	 * @param header The header
	 * @param tableSize The size of the table, in bytes
	 * @param lazy True if this is a lazy binding table; otherwise, false
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	public BindingTable(BinaryReader reader, MachHeader header, int tableSize, boolean lazy)
			throws IOException {
		this();

		int pointerSize = header.getAddressSize();
		long origIndex = reader.getPointerIndex();
		Binding binding = new Binding();

		while (reader.getPointerIndex() < origIndex + tableSize) {

			opcodeOffsets.add(reader.getPointerIndex() - origIndex);
			byte b = reader.readNextByte();
			BindOpcode opcode = BindOpcode.forOpcode(b & BIND_OPCODE_MASK);
			int immediate = b & BIND_IMMEDIATE_MASK;
			
			switch (opcode) {
				case BIND_OPCODE_DONE: { // 0x00
					if (lazy) {
						//bind.lazyOffset = command.getLazyBindSize() - byteStream.available();//Note: this only works because we are using a ByteArrayInputStream!
						break;
					}
					return;
				}
				case BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: { // 0x10
					binding.libraryOrdinal = immediate;
					break;
				}
				case BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: { // 0x20
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					binding.libraryOrdinal = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					break;
				}
				case BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: { // 0x30
					//the special ordinals are negative numbers
					if (immediate == 0) {
						binding.libraryOrdinal = 0;
					}
					else {
						byte signExtended =
							(byte) (DyldInfoCommandConstants.BIND_OPCODE_MASK | immediate);
						binding.libraryOrdinal = signExtended;
					}
					break;
				}
				case BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: { // 0x40
					stringOffsets.add(reader.getPointerIndex() - origIndex);
					binding.symbolName = reader.readNextAsciiString();
					binding.weak =
						(immediate & DyldInfoCommandConstants.BIND_SYMBOL_FLAGS_WEAK_IMPORT) != 0;
					break;
				}
				case BIND_OPCODE_SET_TYPE_IMM: { // 0x50
					binding.type = immediate;
					break;
				}
				case BIND_OPCODE_SET_ADDEND_SLEB: { // 0x60
					slebOffsets.add(reader.getPointerIndex() - origIndex);
					binding.addend = reader.readNext(LEB128::signed);
					break;
				}
				case BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: { // 0x70
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					binding.segmentOffset = reader.readNext(LEB128::unsigned);
					binding.segmentIndex = immediate;
					break;
				}
				case BIND_OPCODE_ADD_ADDR_ULEB: { // 0x80
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					binding.segmentOffset += reader.readNext(LEB128::unsigned);
					break;
				}
				case BIND_OPCODE_DO_BIND: { // 0x90
					bindings.add(new Binding(binding));
					if (threadedBindings == null) {
						binding.segmentOffset += pointerSize;
					}
					break;
				}
				case BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: { // 0xA0
					bindings.add(new Binding(binding));
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					binding.segmentOffset += reader.readNext(LEB128::unsigned) + pointerSize;
					break;
				}
				case BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: { // 0xB0
					bindings.add(new Binding(binding));
					binding.segmentOffset += (immediate * pointerSize) + pointerSize;
					break;
				}
				case BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: { // 0xC0
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					long count = reader.readNext(LEB128::unsigned);
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					long skip = reader.readNext(LEB128::unsigned);
					for ( int i = 0 ; i < count ; ++i ) {
						bindings.add(new Binding(binding));
						binding.segmentOffset += skip + pointerSize;
					}
					break;
				}
				case BIND_OPCODE_THREADED: { // 0xD0
					switch (immediate) {
						case BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB:
							ulebOffsets.add(reader.getPointerIndex() - origIndex);
							int numThreaded = reader.readNextVarInt(LEB128::unsigned);
							threadedBindings = new ArrayList<>(numThreaded);
							break;
						case BIND_SUBOPCODE_THREADED_APPLY: {
							threadedBindings.add(new Binding(binding));
							break;
						}
						default: {
							Binding unknownBinding = new Binding(binding);
							unknownBinding.unknownOpcode = Byte.toUnsignedInt(b);
							bindings.add(unknownBinding);
							return;
						}
					}
					break;
				}
				default: {
					Binding unknownBinding = new Binding(binding);
					unknownBinding.unknownOpcode = Byte.toUnsignedInt(b) & BIND_OPCODE_MASK;
					bindings.add(unknownBinding);
					return;
				}
			}
		}
	}

	/**
	 * {@return the bindings}
	 */
	public List<Binding> getBindings() {
		return bindings;
	}

	/**
	 * {@return the threaded bindings, or null if threaded bindings are not being used}
	 */
	public List<Binding> getThreadedBindings() {
		return threadedBindings;
	}

	/**
	 * A piece of binding information from a {@link BindingTable}
	 */
	public static class Binding {

		private String symbolName;
		private int type;
		private int libraryOrdinal;
		private long segmentOffset;
		private int segmentIndex = -1;
		private long addend;
		private boolean weak;
		private Integer unknownOpcode;

		/**
		 * Creates a new {@link Binding}
		 */
		public Binding() {
			// Nothing to do
		}

		/**
		 * Creates a copy of the given {@link Binding}
		 * 
		 * @param binding The {@link Binding} to copy
		 */
		public Binding(Binding binding) {
			this.symbolName = binding.symbolName;
			this.type = binding.type;
			this.libraryOrdinal = binding.libraryOrdinal;
			this.segmentOffset = binding.segmentOffset;
			this.segmentIndex = binding.segmentIndex;
			this.addend = binding.addend;
			this.weak = binding.weak;
			this.unknownOpcode = binding.unknownOpcode;
		}

		/**
		 * {@return The symbol name}
		 */
		public String getSymbolName() {
			return symbolName;
		}

		/**
		 * {@return The type}
		 */
		public int getType() {
			return type;
		}

		/**
		 * {@return The library ordinal}
		 */
		public int getLibraryOrdinal() {
			return libraryOrdinal;
		}

		/**
		 * {@return The segment offset}
		 */
		public long getSegmentOffset() {
			return segmentOffset;
		}

		/**
		 * {@return The segment index}
		 */
		public int getSegmentIndex() {
			return segmentIndex;
		}

		/**
		 * {@return The addend}
		 */
		public long getAddend() {
			return addend;
		}

		/**
		 * {@return True if the binding is "weak"; otherwise false}
		 */
		public boolean isWeak() {
			return weak;
		}

		/**
		 * {@return null if the opcode is known; otherwise, returns the unknown opcode's value}
		 */
		public Integer getUnknownOpcode() {
			return unknownOpcode;
		}
	}
}
