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
import ghidra.program.model.data.LEB128;

/**
 * A Mach-O rebase table
 */
public class RebaseTable extends OpcodeTable {

	private List<Rebase> rebases = new ArrayList<>();

	/**
	 * Creates an empty {@link RebaseTable}
	 */
	public RebaseTable() {
		super();
	}

	/**
	 * Creates and parses a new {@link RebaseTable}
	 * 
	 * @param reader A {@link BinaryReader reader} positioned at the start of the rebase table
	 * @param header The header
	 * @param tableSize The size of the table, in bytes
	 * @throws IOException if an IO-related error occurs while parsing
	 */
	public RebaseTable(BinaryReader reader, MachHeader header, int tableSize) throws IOException {
		this();

		int pointerSize = header.getAddressSize();
		long origIndex = reader.getPointerIndex();
		Rebase rebase = new Rebase();

		while (reader.getPointerIndex() < origIndex + tableSize) {

			opcodeOffsets.add(reader.getPointerIndex() - origIndex);
			byte b = reader.readNextByte();
			RebaseOpcode opcode = RebaseOpcode.forOpcode(b & REBASE_OPCODE_MASK);
			int immediate = b & REBASE_IMMEDIATE_MASK;
			
			switch (opcode) {
				case REBASE_OPCODE_DONE: { // 0x00
					return;
				}
				case REBASE_OPCODE_SET_TYPE_IMM: { // 0x10
					rebase.type = immediate;
					break;
				}
				case REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: { // 0x20
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					rebase.segmentIndex = immediate;
					rebase.segmentOffset = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					break;
				}
				case REBASE_OPCODE_ADD_ADDR_ULEB: { // 0x30
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					rebase.segmentOffset += reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					break;
				}
				case REBASE_OPCODE_ADD_ADDR_IMM_SCALED: { // 0x40
					rebase.segmentOffset += immediate * pointerSize;
					break;
				}
				case REBASE_OPCODE_DO_REBASE_IMM_TIMES: { // 0x50
					for (int i = 0; i < immediate; ++i) {
						rebases.add(new Rebase(rebase));
						rebase.segmentOffset += pointerSize;
					}
					break;
				}
				case REBASE_OPCODE_DO_REBASE_ULEB_TIMES: { // 0x60
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					int count = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					for (int i = 0; i < count; ++i) {
						rebases.add(new Rebase(rebase));
						rebase.segmentOffset += pointerSize;
					}
					break;
				}
				case REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: { // 0x70
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					rebases.add(new Rebase(rebase));
					rebase.segmentOffset += reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					break;
				}
				case REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: { // 0x80
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					int count = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					ulebOffsets.add(reader.getPointerIndex() - origIndex);
					int skip = reader.readNextUnsignedVarIntExact(LEB128::unsigned);
					for (int i = 0; i < count; ++i) {
						rebases.add(new Rebase(rebase));
						rebase.segmentOffset += skip + pointerSize;
	                }
					break;
				}
				default: {
					Rebase unknownRebase = new Rebase(rebase);
					unknownRebase.unknownOpcode = Byte.toUnsignedInt(b) & REBASE_OPCODE_MASK;
					rebases.add(unknownRebase);
					return;
				}
			}
		}
	}

	/**
	 * {@return the rebases}
	 */
	public List<Rebase> getRebases() {
		return rebases;
	}

	/**
	 * A piece of rebase information from a {@link RebaseTable}
	 */
	public static class Rebase {

		private int type;
		private long segmentOffset;
		private int segmentIndex = -1;
		private Integer unknownOpcode;

		/**
		 * Creates a new {@link Rebase}
		 */
		public Rebase() {
			// Nothing to do
		}

		/**
		 * Creates a copy of the given {@link Rebase}
		 * 
		 * @param rebase The {@link Rebase} to copy
		 */
		public Rebase(Rebase rebase) {
			this.segmentIndex = rebase.segmentIndex;
			this.segmentOffset = rebase.segmentOffset;
			this.type = rebase.type;
			this.unknownOpcode = rebase.unknownOpcode;
		}

		/**
		 * {@return The segment index}
		 */
		public int getSegmentIndex() {
			return segmentIndex;
		}

		/**
		 * {@return The segment offset}
		 */
		public long getSegmentOffset() {
			return segmentOffset;
		}

		/**
		 * {@return The type}
		 */
		public int getType() {
			return type;
		}

		/**
		 * {@return null if the opcode is known; otherwise, returns the unknown opcode's value}
		 */
		public Integer getUnknownOpcode() {
			return unknownOpcode;
		}

		@Override
		public String toString() {
			return "segment: 0x%x, index: 0x%x, kind: %d".formatted(segmentIndex, segmentOffset,
				type);
		}
	}
}
