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
package ghidra.app.util.bin.format.swift;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.swift.types.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.*;

/**
 * Resolves Swift enum layout domains at exact metadata addresses. Unsupported metadata and
 * witnesses produce no proof. This does not associate types with function inputs or loads.
 */
public final class SwiftEnumDomainResolver {
	private static final int MAX_FIELDS = 1 << 16;
	private static final int MAX_NAME_BYTES = 256;
	private static final int MAX_EVIDENCE_BYTES = 1 << 20;
	private static final int MAX_WITNESS_INSTRUCTIONS = 16;
	private final Program program;

	/** @param program program whose metadata and existing instruction listing are inspected */
	public SwiftEnumDomainResolver(Program program) {
		this.program = Objects.requireNonNull(program);
	}

	/**
	 * @param descriptorAddress exact TargetEnumDescriptor address
	 * @return proven domain, or empty for unsupported or malformed data
	 */
	public Optional<SwiftEnumValueDomain> resolveNoPayload(Address descriptorAddress) {
		try { return new Proof().noPayload(descriptorAddress); }
		catch (IOException | AddressOutOfBoundsException | ArithmeticException e) {
			return Optional.empty();
		}
	}

	/**
	 * Proves a selected payload's contiguous byte domain using bounded static value witnesses.
	 * Only a single direct/indirect symbolic reference, little-endian AARCH64, and one-byte
	 * storage are supported. No target code executes and no program data is written.
	 *
	 * @param enumMetadataAddress enum metadata, following its value-witness pointer
	 * @param payloadOrdinal declaration-order payload case
	 * @return layout proof, or empty when any part cannot be proved
	 */
	public Optional<SwiftEnumPayloadDomain> resolvePayload(Address enumMetadataAddress,
			int payloadOrdinal) {
		try { return new Proof().payload(enumMetadataAddress, payloadOrdinal); }
		catch (IOException | AddressOutOfBoundsException | ArithmeticException e) {
			return Optional.empty();
		}
	}

	private final class Proof {
		private final SortedMap<Address, Byte> evidence = new TreeMap<>();
		private final ByteOrder byteOrder = program.getMemory().isBigEndian() ?
			ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN;

		Optional<SwiftEnumValueDomain> noPayload(Address address) throws IOException {
			Descriptor descriptor = descriptor(address);
			return SwiftEnumValueDomain.fromDescriptor(descriptor.type, descriptor.fields);
		}

		Optional<SwiftEnumPayloadDomain> payload(Address metadata, int ordinal) throws IOException {
			int ptr = program.getDefaultPointerSize();
			if (metadata == null || ptr != 8 || program.getMemory().isBigEndian() || ordinal < 0 ||
				!program.getLanguage().getProcessor().toString().equals("AARCH64")) {
				return Optional.empty();
			}
			if (longAt(metadata) != 0x201) { return Optional.empty(); }
			Address descriptorAddress = pointerAt(metadata.add(ptr));
			Descriptor descriptor = descriptor(descriptorAddress);
			int payloads = descriptor.type.getNumPayloadCases();
			if (ordinal >= payloads || payloads + descriptor.type.getNumEmptyCasesUnsigned() > 256) {
				return Optional.empty();
			}
			FieldRecord field = descriptor.fields.getFieldRecords().get(ordinal);
			if (field.getMangledTypeNameAddress().isEmpty()) { return Optional.empty(); }
			Address reference = descriptorAddress.getAddressSpace()
				.getAddress(field.getMangledTypeNameAddress().orElseThrow());
			byte[] ref = bytes(reference, 6);
			int opcode = Byte.toUnsignedInt(ref[0]);
			if ((opcode != 1 && opcode != 2) || ref[5] != 0) { return Optional.empty(); }
			int displacement = ByteBuffer.wrap(ref, 1, 4).order(byteOrder).getInt();
			Address payloadDescriptor = reference.add(1).add(displacement);
			if (opcode == 2) { payloadDescriptor = pointerAt(payloadDescriptor); }
			Optional<SwiftEnumValueDomain> child = noPayload(payloadDescriptor);
			if (child.isEmpty() || child.get().getStorageSize() != 1) { return Optional.empty(); }
			Address vwt = pointerAt(metadata.subtract(ptr));
			// Eight required function pointers, size, stride, flags (u32), extra inhabitants (u32).
			int sizeOffset = 8 * ptr;
			int strideOffset = sizeOffset + ptr;
			int enumOffset = strideOffset + ptr + 2 * Integer.BYTES;
			bytes(vwt, enumOffset + 3 * ptr);
			if (longAt(vwt.add(sizeOffset)) != 1 || longAt(vwt.add(strideOffset)) != 1) {
				return Optional.empty();
			}
			List<Address> addresses = List.of(pointerAt(vwt.add(enumOffset)),
				pointerAt(vwt.add(enumOffset + ptr)), pointerAt(vwt.add(enumOffset + 2 * ptr)));
			Routine getTag = routine(addresses.get(0));
			Routine project = routine(addresses.get(1));
			Routine inject = routine(addresses.get(2));
			int count = (int) child.get().getCaseCount();
			int[] canonical = new int[count];
			SortedSet<Integer> encodings = new TreeSet<>();
			for (int value = 0; value < count; value++) {
				int encoded = run(inject, value, ordinal, false).value;
				if (!encodings.add(encoded) || run(getTag, encoded, null, true).returned != ordinal ||
					run(project, encoded, null, false).value != value) { return Optional.empty(); }
				canonical[value] = encoded;
			}
			SortedSet<Integer> recovered = new TreeSet<>();
			for (int raw = 0; raw < 256; raw++) {
				Result tag = run(getTag, raw, null, true);
				if (tag.value != raw) { return Optional.empty(); }
				if (tag.returned != ordinal) { continue; }
				int projected = run(project, raw, null, false).value;
				if (!child.get().contains(projected)) { continue; }
				if (canonical[projected] != raw || run(inject, projected, ordinal, false).value != raw) {
					return Optional.empty();
				}
				recovered.add(raw);
			}
			if (!recovered.equals(encodings) || encodings.last() - encodings.first() + 1 != count) {
				return Optional.empty();
			}
			return Optional.of(new SwiftEnumPayloadDomain(metadata, descriptorAddress,
				payloadDescriptor, ordinal, encodings.first(), encodings.last(), addresses,
				digest(ordinal)));
		}

		private Descriptor descriptor(Address address) throws IOException {
			if (address == null || !address.isMemoryAddress()) { throw unsupported(); }
			bytes(address, 28);
			int flags = intAt(address);
			// Generic, versioned, and trailing initialization extensions are unsupported here.
			if ((flags & 0x1f) != ContextDescriptorKind.Enum.getValue() || (flags & ~0x5f) != 0) {
				throw unsupported();
			}
			long payloads = Integer.toUnsignedLong(intAt(address.add(20)) & 0x00ffffff);
			long total = payloads + Integer.toUnsignedLong(intAt(address.add(24)));
			if (total < 2 || total > MAX_FIELDS) { throw unsupported(); }
			terminated(relativeAt(address.add(8)));
			Address fields = relativeAt(address.add(16));
			ByteBuffer header = ByteBuffer.wrap(bytes(fields, FieldDescriptor.SIZE)).order(byteOrder);
			int expectedKind = payloads > 1 ? 3 : 2; // MultiPayloadEnum or ordinary Enum
			if (Short.toUnsignedInt(header.getShort(8)) != expectedKind ||
				Short.toUnsignedInt(header.getShort(10)) != FieldRecord.SIZE ||
				Integer.toUnsignedLong(header.getInt(12)) != total) { throw unsupported(); }
			if (intAt(fields) != 0) { terminated(relativeAt(fields)); }
			bytes(fields.add(FieldDescriptor.SIZE), (int) total * FieldRecord.SIZE);
			for (int i = 0; i < total; i++) {
				Address field = fields.add(FieldDescriptor.SIZE + (long) i * FieldRecord.SIZE);
				boolean hasPayloadType = intAt(field.add(4)) != 0;
				if ((i < payloads) != hasPayloadType) { throw unsupported(); }
				if (hasPayloadType) { terminated(relativeAt(field.add(4))); }
				terminated(relativeAt(field.add(8)));
			}
			try (MemoryByteProvider provider = new MemoryByteProvider(program.getMemory(),
				address.getAddressSpace())) {
				BinaryReader reader = new BinaryReader(provider, byteOrder == ByteOrder.LITTLE_ENDIAN);
				reader.setPointerIndex(address.getOffset());
				TargetEnumDescriptor type = new TargetEnumDescriptor(reader);
				reader.setPointerIndex(fields.getOffset());
				return new Descriptor(type, new FieldDescriptor(reader));
			}
		}

		private Address relativeAt(Address field) throws IOException {
			int offset = intAt(field);
			if (offset == 0) { throw unsupported(); }
			return field.add(offset);
		}
		private Address pointerAt(Address field) throws IOException {
			long value = longAt(field);
			if (value == 0) { throw unsupported(); }
			return field.getAddressSpace().getAddress(value);
		}
		private void terminated(Address address) throws IOException {
			for (int i = 0; i < MAX_NAME_BYTES; i++) {
				if (bytes(address.add(i), 1)[0] == 0) { return; }
			}
			throw unsupported();
		}
		private int intAt(Address address) throws IOException {
			return ByteBuffer.wrap(bytes(address, 4)).order(byteOrder).getInt();
		}
		private long longAt(Address address) throws IOException {
			return ByteBuffer.wrap(bytes(address, 8)).order(byteOrder).getLong();
		}
		private byte[] bytes(Address address, int count) throws IOException {
			if (count < 0 || count > MAX_EVIDENCE_BYTES) { throw unsupported(); }
			byte[] result = new byte[count];
			try {
				if (program.getMemory().getBytes(address, result) != count) { throw unsupported(); }
			}
			catch (MemoryAccessException e) { throw new IOException(e); }
			for (int i = 0; i < result.length; i++) {
				Address at = address.add(i);
				Byte old = evidence.get(at);
				if (old != null && old != result[i]) { throw unsupported(); }
				if (old == null) {
					if (evidence.size() == MAX_EVIDENCE_BYTES) { throw unsupported(); }
					evidence.put(at, result[i]);
				}
			}
			return result;
		}

		private Routine routine(Address entry) throws IOException {
			List<PcodeOp[]> instructions = new ArrayList<>();
			Address cursor = entry;
			for (int i = 0; i < MAX_WITNESS_INSTRUCTIONS; i++) {
				Instruction instruction = program.getListing().getInstructionAt(cursor);
				if (instruction == null || instruction.getFlowType().isCall()) { throw unsupported(); }
				try {
					if (!Arrays.equals(bytes(cursor, instruction.getLength()), instruction.getBytes())) {
						throw unsupported();
					}
				}
				catch (MemoryAccessException e) { throw new IOException(e); }
				PcodeOp[] operations = instruction.getPcode(false);
				if (operations.length == 0 || operations.length > 64) { throw unsupported(); }
				if (operations[operations.length - 1].getOpcode() == PcodeOp.RETURN) {
					// AARCH64 RET copies the ABI link register into PC. The return address is
					// control flow only, never an assumed constant available to the value proof.
					Register pc = program.getLanguage().getProgramCounter();
					Register link = program.getRegister("x30");
					if (!instruction.getFlowType().isTerminal() || operations.length != 2 ||
						operations[0].getOpcode() != PcodeOp.COPY ||
						!sameRegister(operations[0].getOutput(), pc) ||
						!sameRegister(operations[0].getInput(0), link) ||
						!operations[1].getInput(0).equals(operations[0].getOutput())) {
						throw unsupported();
					}
					instructions.add(new PcodeOp[] { operations[1] });
					return new Routine(instructions);
				}
				instructions.add(operations);
				for (int j = 0; j < operations.length; j++) {
					if (!supported(operations[j].getOpcode())) { throw unsupported(); }
					if (operations[j].getOpcode() == PcodeOp.RETURN) {
						if (j != operations.length - 1) { throw unsupported(); }
						return new Routine(instructions);
					}
				}
				cursor = instruction.getFallThrough();
				if (cursor == null) { throw unsupported(); }
			}
			throw unsupported();
		}

		private Result run(Routine routine, int value, Integer tag, boolean returnsTag) throws IOException {
			State state = new State(value);
			state.pointerRegister("x0");
			if (tag != null) { state.register("x1", tag); }
			for (PcodeOp[] instruction : routine.instructions) {
				state.temporaries.clear();
				for (PcodeOp op : instruction) {
					int opcode = op.getOpcode();
					if (opcode == PcodeOp.RETURN) {
						return new Result(state.value, returnsTag ? state.register("x0") : 0);
					}
					if (opcode == PcodeOp.LOAD || opcode == PcodeOp.STORE) {
						Varnode space = op.getInput(0);
						if (!space.isConstant() || space.getOffset() != Integer.toUnsignedLong(
							program.getAddressFactory().getDefaultAddressSpace().getSpaceID()) ||
							!state.readValue(op.getInput(1)).fullPointer) { throw unsupported(); }
						if (opcode == PcodeOp.LOAD && op.getOutput().getSize() == 1) {
							state.write(op.getOutput(), state.value);
						}
						else if (opcode == PcodeOp.STORE && op.getInput(2).getSize() == 1) {
							state.value = (int) state.read(op.getInput(2)) & 0xff;
						}
						else { throw unsupported(); }
						continue;
					}
					Varnode input = op.getInput(0);
					if (opcode == PcodeOp.COPY) {
						Value copied = state.readValue(input);
						if (copied.pointer) {
							if (!copied.fullPointer) { throw unsupported(); }
							state.writePointer(op.getOutput());
						}
						else { state.write(op.getOutput(), copied.bits); }
						continue;
					}
					if (opcode == PcodeOp.INT_ADD) {
						Value a = state.readValue(input);
						Value b = state.readValue(op.getInput(1));
						if (a.pointer || b.pointer) {
							if ((a.fullPointer && !b.pointer && b.bits == 0) ||
								(b.fullPointer && !a.pointer && a.bits == 0)) {
								state.writePointer(op.getOutput());
								continue;
							}
							throw unsupported();
						}
					}
					long left = state.read(input);
					long right = op.getNumInputs() > 1 ? state.read(op.getInput(1)) : 0;
					long result = switch (opcode) {
						case PcodeOp.COPY, PcodeOp.INT_ZEXT -> left;
						case PcodeOp.INT_SEXT -> signed(left, input.getSize());
						case PcodeOp.INT_AND -> left & right;
						case PcodeOp.INT_OR -> left | right;
						case PcodeOp.INT_XOR -> left ^ right;
						case PcodeOp.INT_ADD -> left + right;
						case PcodeOp.INT_SUB -> left - right;
						case PcodeOp.INT_LEFT -> Long.compareUnsigned(right, input.getSize() * 8L) >= 0
							? 0 : left << (int) right;
						case PcodeOp.INT_RIGHT -> Long.compareUnsigned(right, input.getSize() * 8L) >= 0
							? 0 : left >>> (int) right;
						case PcodeOp.INT_SRIGHT -> Long.compareUnsigned(right, input.getSize() * 8L) >= 0
							? (signed(left, input.getSize()) < 0 ? -1 : 0)
							: signed(left, input.getSize()) >> (int) right;
						case PcodeOp.SUBPIECE -> Long.compareUnsigned(right, input.getSize()) >= 0
							? 0 : left >>> ((int) right * 8);
						default -> throw unsupported();
					};
					state.write(op.getOutput(), result);
				}
			}
			throw unsupported();
		}

		private String digest(int ordinal) throws IOException {
			try {
				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				digest.update(ByteBuffer.allocate(4).putInt(ordinal).array());
				for (Map.Entry<Address, Byte> entry : evidence.entrySet()) {
					Address address = entry.getKey();
					digest.update(ByteBuffer.allocate(12).putInt(address.getAddressSpace().getSpaceID())
						.putLong(address.getOffset()).array());
					digest.update(entry.getValue());
				}
				return HexFormat.of().formatHex(digest.digest());
			}
			catch (NoSuchAlgorithmException e) { throw new IOException(e); }
		}
	}

	private final class State {
		private final Map<StorageByte, StorageValue> registers = new HashMap<>();
		private final Map<StorageByte, StorageValue> temporaries = new HashMap<>();
		private int value;
		State(int value) { this.value = value; }
		void register(String name, long value) throws IOException {
			Register register = program.getRegister(name);
			if (register == null || register.getMinimumByteSize() != 8) { throw unsupported(); }
			write(new Varnode(register.getAddress(), register.getMinimumByteSize()), value);
		}
		long register(String name) throws IOException {
			Register register = program.getRegister(name);
			if (register == null) { throw unsupported(); }
			return read(new Varnode(register.getAddress(), register.getMinimumByteSize()));
		}
		void pointerRegister(String name) throws IOException {
			Register register = program.getRegister(name);
			if (register == null || register.getMinimumByteSize() != 8) { throw unsupported(); }
			writePointer(new Varnode(register.getAddress(), 8));
		}

		Value readValue(Varnode node) throws IOException {
			if (node.isConstant()) {
				return new Value(node.getOffset() & mask(node.getSize()), false, false);
			}
			Map<StorageByte, StorageValue> bank = bank(node);
			long result = 0;
			boolean pointer = false;
			boolean fullPointer = node.getSize() == 8;
			for (int i = 0; i < node.getSize(); i++) {
				StorageValue stored = bank.get(key(node, i));
				if (stored == null) { throw unsupported(); }
				pointer |= stored.pointerByte >= 0;
				fullPointer &= stored.pointerByte == i;
				result |= Byte.toUnsignedLong(stored.bits) << (8 * i);
			}
			return new Value(result, pointer, pointer && fullPointer);
		}

		long read(Varnode node) throws IOException {
			Value read = readValue(node);
			if (read.pointer) { throw unsupported(); }
			return read.bits;
		}

		void write(Varnode node, long value) throws IOException {
			Map<StorageByte, StorageValue> bank = bank(node);
			for (int i = 0; i < node.getSize(); i++) {
				bank.put(key(node, i), new StorageValue((byte) (value >>> (8 * i)), -1));
			}
		}

		void writePointer(Varnode node) throws IOException {
			if (node.getSize() != 8) { throw unsupported(); }
			Map<StorageByte, StorageValue> bank = bank(node);
			for (int i = 0; i < 8; i++) {
				// No concrete address is chosen. Provenance survives aliases byte by byte.
				bank.put(key(node, i), new StorageValue((byte) 0, i));
			}
		}
		private StorageByte key(Varnode node, int byteOffset) {
			return new StorageByte(node.getAddress().getAddressSpace().getSpaceID(),
				node.getOffset() + byteOffset);
		}
		private Map<StorageByte, StorageValue> bank(Varnode node) throws IOException {
			if (node.getSize() < 1 || node.getSize() > 8) { throw unsupported(); }
			if (node.isRegister()) { return registers; }
			if (node.isUnique()) { return temporaries; }
			throw unsupported();
		}
	}

	private static boolean sameRegister(Varnode node, Register register) {
		return node != null && register != null && node.getAddress().equals(register.getAddress()) &&
			node.getSize() == register.getMinimumByteSize();
	}

	private static long mask(int size) throws IOException {
		if (size < 1 || size > 8) { throw unsupported(); }
		return size == 8 ? -1L : (1L << (8 * size)) - 1;
	}
	private static long signed(long value, int size) {
		int shift = Long.SIZE - size * 8;
		return value << shift >> shift;
	}
	private static boolean supported(int opcode) {
		return switch (opcode) {
			case PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.INT_AND,
				PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT,
				PcodeOp.INT_SRIGHT, PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.SUBPIECE,
				PcodeOp.LOAD, PcodeOp.STORE, PcodeOp.RETURN -> true;
			default -> false;
		};
	}
	private static IOException unsupported() {
		return new IOException("Unsupported or inconsistent Swift enum metadata/witness layout");
	}
	private record Value(long bits, boolean pointer, boolean fullPointer) {}
	private record StorageValue(byte bits, int pointerByte) {}
	private record StorageByte(int spaceID, long offset) {}
	private record Descriptor(TargetEnumDescriptor type, FieldDescriptor fields) {}
	private record Routine(List<PcodeOp[]> instructions) {}
	private record Result(int value, long returned) {}
}
