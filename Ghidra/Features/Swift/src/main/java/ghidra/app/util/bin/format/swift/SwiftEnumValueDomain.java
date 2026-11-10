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

import java.util.*;

import ghidra.app.util.bin.format.swift.types.*;

/**
 * A proven closed discriminator domain for a non-generic, no-payload Swift enum.
 * This does not bind the domain to any function input or arbitrary memory location.
 *
 * <p>The Swift ABI assigns no-payload cases consecutive tags in declaration order, using the
 * minimum integer bit width that contains every case. Tags after the final case are extra
 * inhabitants, rather than additional valid values.</p>
 *
 * @see <a href="https://github.com/swiftlang/swift/blob/main/docs/ABI/TypeLayout.rst">Swift type layout</a>
 */
public final class SwiftEnumValueDomain {

	// Wider integers need target ABI layout information in addition to the minimal tag bit width.
	private static final long MAX_SUPPORTED_CASE_COUNT = 1L << Short.SIZE;

	private final long descriptorAddress;
	private final long caseCount;
	private final int bitSize;
	private final List<String> caseNames;

	private SwiftEnumValueDomain(long descriptorAddress, long caseCount, List<String> caseNames) {
		this.descriptorAddress = descriptorAddress;
		this.caseCount = caseCount;
		bitSize = Long.SIZE - Long.numberOfLeadingZeros(caseCount - 1);
		this.caseNames = List.copyOf(caseNames);
	}

	/**
	 * Derives a domain only when the descriptor and its field records prove a supported layout.
	 * Payload enums, generic enums, empty/single-case enums, unknown descriptor versions and
	 * inconsistent reflection records have no domain here. This model supports at most a 16-bit
	 * integer tag; wider integer storage layouts require additional target ABI information.
	 *
	 * @param descriptor the enum descriptor
	 * @param fields the referenced field descriptor
	 * @return the proven domain, or empty for inconsistent or unsupported metadata
	 */
	public static Optional<SwiftEnumValueDomain> fromDescriptor(TargetEnumDescriptor descriptor,
			FieldDescriptor fields) {
		if (descriptor == null || fields == null ||
			descriptor.getFlags().getKind() != ContextDescriptorKind.Enum ||
			descriptor.getFlags().isGeneric() ||
			(descriptor.getFlags().getFlags() & 0xff00) != 0 ||
			descriptor.getNumPayloadCases() != 0 || descriptor.getFields() == 0 ||
			descriptor.getName() == null || descriptor.getName().isBlank()) {
			return Optional.empty();
		}
		long count = descriptor.getNumEmptyCasesUnsigned();
		List<FieldRecord> records = fields.getFieldRecords();
		if (count < 2 || count > MAX_SUPPORTED_CASE_COUNT || fields.getKind() != 2 ||
			fields.getFieldRecordSize() != FieldRecord.SIZE ||
			Integer.toUnsignedLong(fields.getNumFields()) != count || records.size() != count) {
			return Optional.empty();
		}
		long fieldAddress;
		try {
			fieldAddress = Math.addExact(Math.addExact(descriptor.getBase(),
				TargetContextDescriptor.SIZE + 8), descriptor.getFields());
		}
		catch (ArithmeticException e) {
			return Optional.empty();
		}
		if (fields.getBase() != fieldAddress) {
			return Optional.empty();
		}
		List<String> names = new ArrayList<>();
		Set<String> uniqueNames = new HashSet<>();
		for (int i = 0; i < records.size(); i++) {
			FieldRecord record = records.get(i);
			String name = record == null ? null : record.getFieldName();
			if (record == null ||
				record.getBase() != fieldAddress + FieldDescriptor.SIZE + (long) i * FieldRecord.SIZE ||
				record.getMangledTypeNameOffset() != 0 || name == null || name.isBlank() ||
				!uniqueNames.add(name)) {
				return Optional.empty();
			}
			names.add(name);
		}
		return Optional.of(new SwiftEnumValueDomain(descriptor.getBase(), count, names));
	}

	/** {@return the identity of the enum descriptor, without a bare-name lookup} */
	public long getDescriptorAddress() {
		return descriptorAddress;
	}

	/** {@return the number of legal consecutive discriminators, starting at zero} */
	public long getCaseCount() {
		return caseCount;
	}

	/** {@return the minimum integer bit width needed to contain all cases} */
	public int getBitSize() {
		return bitSize;
	}

	/**
	 * {@return the bytes containing the integer tag bits; this does not describe alignment or
	 * aggregate stride}
	 */
	public int getStorageSize() {
		return (bitSize + Byte.SIZE - 1) / Byte.SIZE;
	}

	/** {@return an immutable snapshot of case names in discriminator order} */
	public List<String> getCaseNames() {
		return caseNames;
	}

	/**
	 * Tests whether a discriminator is a legal value of this proven enum contract.
	 *
	 * @param value the discriminator
	 * @return whether the discriminator is in the closed domain
	 */
	public boolean contains(long value) {
		return value >= 0 && value < caseCount;
	}
}
