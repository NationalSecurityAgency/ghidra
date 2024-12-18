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
package ghidra.app.util.bin.format.pdb;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Consumer;

import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.datastruct.RangeMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>CompositeMember</code> provides the ability to process PDB data-type records and
 * incrementally build-up composite structure and union data-types from a flattened offset-based
 * list of members which may include embedded anonymous composite members.  Composite members
 * correspond to either hard predefined data-types, or structure/union containers whose members
 * are added and refined incrementally.
 * <p>
 * Container members are characterized by a null data-type name, zero length, and will be
 * identified as either a structure or union.
 */
public class DefaultCompositeMember extends CompositeMember {

	private static int MAX_CONSTRUCTION_DEPTH = 20;

	private static final String PADDING_COMPONENT_NAME = "_padding_";

	private DataTypeManager dataTypeManager;
	private Consumer<String> errorConsumer;

	private DefaultCompositeMember parent; // parent container (null if this is root container)

	private boolean isClass; // true for root container which corresponds to class structure

	private String memberName; // null if this is a root container
	private String memberDataTypeName; // null if this is a container
	private int memberOffset; // member offset relative to start of parent container
	private String memberComment; // may be null if unspecified
	private MemberType memberType; // type of member (e.g., STRUCTURE, UNION, MEMBER)
	private int memberLength; // container members have 0 length (rely on memberDataType)

	private DataType memberDataType;
	private boolean memberIsZeroLengthArray;
	private BitFieldGroupCompositeMember bitFieldGroup;

	// Structure container data
	private TreeMap<Integer, CompositeMember> structureMemberOffsetMap;
	private RangeMap structureMemberRangeMap;
	private int largestPrimitiveSize;
	private boolean hasPadding = false;

	// Union container data
	private List<CompositeMember> unionMemberList;

	private static long nextTemporaryValue;

	private static synchronized String allocateTemporaryContainerName(String type) {
		return "_tmp_" + type + nextTemporaryValue++;
	}

	/**
	 * Construct the outermost root container member for a new composite data-type.
	 * @param isClass true if container corresponds to a Class structure, else false
	 * @param editComposite composite to be built-up (must have program's datatype manager)
	 * @param errorConsumer error consumer (may be null)
	 * @throws CancelledException if task is cancelled
	 */
	private DefaultCompositeMember(boolean isClass, Composite editComposite,
			Consumer<String> errorConsumer) throws CancelledException {
		this.isClass = isClass;
		memberDataType = editComposite;
		memberOffset = -1;
		this.dataTypeManager = editComposite.getDataTypeManager();
		this.errorConsumer = errorConsumer;
		initializeContainer();
	}

	/**
	 * Construct a new composite member from a PDB data-type member record.
	 * @param member PDB member record
	 * @param dataTypeManager program's datatype manager
	 * @param errorConsumer error consumer (may be null)
	 * @param monitor task monitor
	 * @throws CancelledException if task is cancelled
	 * @throws DataTypeDependencyException if datatype dependency cannot be resolved
	 */
	private DefaultCompositeMember(PdbMember member, DataTypeManager dataTypeManager,
			Consumer<String> errorConsumer, TaskMonitor monitor)
			throws DataTypeDependencyException, CancelledException {

		memberName = member.memberName;
		memberDataTypeName = member.memberDataTypeName;
		memberOffset = member.memberOffset;
		memberComment = member.memberComment;
		memberType = MemberType.MEMBER;
		memberLength = 0; // n/a for regular members
		this.dataTypeManager = dataTypeManager;

		WrappedDataType wrappedDataType = member.getDataType();
		if (wrappedDataType == null) {
			throw new DataTypeDependencyException(
				"Failed to resolve datatype " + memberDataTypeName + " " + memberName);
		}
		memberDataType = wrappedDataType.getDataType().clone(dataTypeManager);
		memberIsZeroLengthArray = wrappedDataType.isZeroLengthArray();
	}

	/**
	 * Construct a new composite member by cloning an existing member.
	 * This is intended for use when establishing nested anonymous unions and structures.
	 * @param member composite member to be cloned
	 */
	private DefaultCompositeMember(DefaultCompositeMember member) {
		memberName = member.memberName;
		memberDataTypeName = member.memberDataTypeName;
		memberDataType = member.memberDataType;
		memberIsZeroLengthArray = member.memberIsZeroLengthArray;
		memberOffset = member.memberOffset;
		memberComment = member.memberComment;
		memberType = member.memberType;
		memberLength = member.memberLength;
		errorConsumer = member.errorConsumer;
		dataTypeManager = member.dataTypeManager;
		structureMemberOffsetMap = member.structureMemberOffsetMap;
		structureMemberRangeMap = member.structureMemberRangeMap;
		// allow padding size to use pointer-size and smaller by default
		largestPrimitiveSize = member.dataTypeManager.getDataOrganization().getPointerSize();
		unionMemberList = member.unionMemberList;
	}

	/**
	 * Construct a filler/padding bitfield member
	 * @param componentOffset member offset within parent
	 * @param baseDataType bitfield base datatype
	 * @param bitSize bitfield size in bits
	 * @param bitOffsetWithinBaseType offset of bitfield within base type
	 * @throws InvalidDataTypeException invalid baseDataType for bitfield
	 */
	private DefaultCompositeMember(int componentOffset, DataType baseDataType, int bitSize,
			int bitOffsetWithinBaseType) throws InvalidDataTypeException {
		memberName = PADDING_COMPONENT_NAME;
		memberDataType = new PdbBitField(baseDataType, bitSize, bitOffsetWithinBaseType);
		memberIsZeroLengthArray = false;
		memberOffset = componentOffset;
		memberType = MemberType.MEMBER;
		memberLength = baseDataType.getLength();
		dataTypeManager = baseDataType.getDataTypeManager();
	}

	@Override
	DefaultCompositeMember getParent() {
		return parent;
	}

	@Override
	void setParent(DefaultCompositeMember newParent) {
		parent = newParent;
	}

	/**
	 * Get member name to be used within parent composite definition
	 * @return member name or null if this is root container
	 */
	private String getName() {
		return memberName;
	}

	/**
	 * Get the data type name associated with this member.  Anonymous inner composite
	 * types will utilize a generated named based upon its parent type name and the
	 * offset at which it occurs within its parent.
	 * @return data type name associated with this member
	 */
	private String getDataTypeName() {
		return memberDataType != null ? memberDataType.getName() : memberDataTypeName;
	}

	/**
	 * Get the data type associated with this member.  Container members data-type
	 * may continue to transform as additional members are added.
	 * @return data type associated with this member.
	 */
	DataType getDataType() {
		return memberDataType;
	}

	private void updateContainerNameAndCategoryPath(String typeMnemonic) {
		if (parent == null || !isContainer()) {
			return; // only non-root container may be renamed
		}
		String baseName = parent.getDataTypeName();
		String oldMemberName = memberName;
		String name = "_" + typeMnemonic + "_";
		if (parent.isUnionContainer()) {
			try {
				name += parent.getOrdinal(oldMemberName);
			}
			catch (NotFoundException e) {
				Msg.error(this, "Failed to rename anonymous compsite: " + getDataTypeName());
			}
		}
		else {
			name += memberOffset;
		}
		try {
			memberDataType.setName(baseName + name);
			memberDataType.setCategoryPath(parent.getChildCategoryPath());

			memberName = name;
			parent.memberNameChanged(oldMemberName, memberName);
		}
		catch (InvalidNameException | DuplicateNameException e) {
			// exceptions are unexpected
			throw new AssertException(e);
		}
	}

	private void transformLastMemberIntoFlexArray(CompositeMember lastMember) {
		if (!(lastMember instanceof DefaultCompositeMember)) {
			return;
		}
		DefaultCompositeMember m = (DefaultCompositeMember) lastMember;
		if (m.memberIsZeroLengthArray) {
			// transform last member into flexible array
			Structure struct = (Structure) memberDataType;
			Array array = (Array) m.getDataType();
			// TODO: there may be a more direct approach since we now handle zero-length array instantiation
			struct.delete(struct.getNumComponents() - 1); // delete placeholder component
			struct.insertAtOffset(m.memberOffset,
				new ArrayDataType(array.getDataType(), 0, 1, dataTypeManager), 0, m.getName(),
				m.memberComment); // use unmodified comment
		}
	}

	@Override
	void finalizeDataType(int preferredSize) {
		if (!isContainer()) {
			return;
		}
		if (isStructureContainer()) {
			updateContainerNameAndCategoryPath("s");
			CompositeMember lastMember = null;
			for (CompositeMember member : structureMemberOffsetMap.values()) {
				member.finalizeDataType(0);
				lastMember = member;
			}
			transformLastMemberIntoFlexArray(lastMember);

			// remove trailing fat caused by use of insert operations
			adjustSize(preferredSize);
		}
		else if (isUnionContainer()) {
			updateContainerNameAndCategoryPath("u");
			for (CompositeMember member : unionMemberList) {
				member.finalizeDataType(0);
			}
		}
		alignComposite(preferredSize);
	}

	/**
	 * Adjust non-packed structure following member reconstruction.
	 * @param preferredSize preferred size
	 */
	private void adjustSize(int preferredSize) {
		if (!isStructureContainer()) {
			return;
		}
		Structure struct = (Structure) getDataType();

		if (struct.isNotYetDefined() && preferredSize > 0) {
			// handle special case of empty structure
			struct.growStructure(preferredSize);
			return;
		}

		if (struct.getLength() < preferredSize) {
			struct.growStructure(preferredSize - struct.getLength());
			return;
		}

		DataTypeComponent dtc = struct.getComponentContaining(preferredSize);
		if (dtc == null) {
			return;
		}

		int startOrdinal = dtc.getOrdinal();
		if (dtc.getOffset() != preferredSize) {
			++startOrdinal;
		}

		for (int i = struct.getNumComponents() - 1; i >= startOrdinal; i--) {
			DataTypeComponent comp = struct.getComponent(i);
			if (comp.getDataType() != DataType.DEFAULT) {
				break;
			}
			struct.delete(i);
		}
	}

	/**
	 * Align container composite data type if possible.
	 * @param preferredSize preferred size of composite if known, else <= 0 if unknown
	 */
	private void alignComposite(int preferredSize) {

		Composite composite = (Composite) memberDataType;

		// don't attempt to align empty composite - don't complain
		if (isStructureContainer()) {
			if (structureMemberOffsetMap.isEmpty()) {
				return;
			}
		}
		else if (unionMemberList.isEmpty()) {
			return;
		}

		Composite copy = (Composite) composite.copy(dataTypeManager);

		int pack = 0;
		copy.setToDefaultPacking();

		boolean alignOK = isGoodAlignment(copy, preferredSize);
		if (alignOK) {
			composite.setToDefaultPacking();
			if (hasPadding) {
				removeUnnecessaryPadding(composite);
			}
		}
		else {
			if (preferredSize > 0 && copy.getLength() != preferredSize) {
				copy.setToMachineAligned(); // will only impact structure length
				alignOK = isGoodAlignment(copy, preferredSize);
				if (alignOK) {
					composite.setToDefaultPacking();
					composite.setToMachineAligned();
					if (hasPadding) {
						removeUnnecessaryPadding(composite);
					}
				}
				else {
					copy.setToDefaultAligned(); // restore default alignment
				}
			}
			if (!alignOK) {
				removeAllPadding(composite); // includes bit-field padding
				if (!hasPadding) {
					pack = 1;
					copy.setExplicitPackingValue(pack);
					alignOK = isGoodAlignment(copy, preferredSize);
					if (alignOK) {
						composite.setExplicitPackingValue(pack);
					}
				}
			}
		}
		if (!alignOK && errorConsumer != null && !isClass) { // don't complain about Class structs which always fail
			String anonymousStr = parent != null ? " anonymous " : "";
			errorConsumer.accept("PDB " + anonymousStr + memberType +
				" reconstruction failed to align " + composite.getPathName());
		}
	}

	private void removeUnnecessaryPadding(Composite packedComposite) {
		if (!packedComposite.isPackingEnabled()) {
			throw new IllegalArgumentException("composite must have packing enabled");
		}
		if (!(packedComposite instanceof Structure struct)) {
			return;
		}
		int preferredLength = packedComposite.getLength();
		DataTypeComponent[] definedComponents = struct.getDefinedComponents();
		int lastIndex = definedComponents.length - 1;
		for (int i = 0; i < definedComponents.length; i++) {
			DataTypeComponent dtc = definedComponents[i];
			if (!isPaddingComponent(dtc, true)) {
				continue; // leave bitfield padding intact
			}
			int nextComponentOffset = -1;
			if (i < lastIndex) {
				nextComponentOffset = definedComponents[i + 1].getOffset();
			}
			int ordinal = dtc.getOrdinal();

			// experiment with padding removal and restore if removal impacts structure
			struct.delete(ordinal);

			if (struct.getLength() != preferredLength || (nextComponentOffset > 0 &&
				nextComponentOffset != definedComponents[i + 1].getOffset())) {
				// restore padding component
				struct.insert(ordinal, dtc.getDataType(), -1, PADDING_COMPONENT_NAME, null);
			}
		}
	}

	private void removeAllPadding(Composite composite) {
		if (!(composite instanceof Structure struct)) {
			return;
		}
		boolean doDelete = composite.isPackingEnabled();
		DataTypeComponent[] definedComponents = struct.getDefinedComponents();
		for (int i = definedComponents.length - 1; i >= 0; i--) {
			DataTypeComponent dtc = definedComponents[i];
			if (isPaddingComponent(dtc, false)) {
				if (doDelete) {
					struct.delete(dtc.getOrdinal());
				}
				else {
					struct.clearComponent(dtc.getOrdinal());
				}
			}
		}
	}

	private boolean isPaddingComponent(DataTypeComponent dtc, boolean skipBitFields) {
		if (skipBitFields && dtc.isBitFieldComponent()) {
			return false;
		}
		return PADDING_COMPONENT_NAME.equals(dtc.getFieldName());
	}

	private boolean isGoodAlignment(Composite testComposite, int preferredSize) {
		boolean alignOK = true;
		if (preferredSize > 0 && testComposite.getNumComponents() != 0) {
			alignOK = (testComposite.getLength() == preferredSize);
		}

		if (alignOK && isStructureContainer()) {
			// verify that components did not move
			Structure struct = (Structure) memberDataType;
			DataTypeComponent[] nonPackedComponents = struct.getDefinedComponents();
			int index = 0;
			for (DataTypeComponent dtc : testComposite.getComponents()) {
				DataTypeComponent nonPackedDtc = nonPackedComponents[index++];
				if (!isComponentUnchanged(dtc, nonPackedDtc)) {
					alignOK = false;
					break;
				}
			}
		}
		return alignOK;
	}

	private boolean isComponentUnchanged(DataTypeComponent dtc, DataTypeComponent nonPackedDtc) {
		if (nonPackedDtc.getOffset() != dtc.getOffset() ||
			nonPackedDtc.getLength() != dtc.getLength() ||
			nonPackedDtc.isBitFieldComponent() != dtc.isBitFieldComponent()) {
			return false;
		}
		if (dtc.isBitFieldComponent()) {
			// both components are bit fields
			BitFieldDataType bitfieldDt = (BitFieldDataType) dtc.getDataType();
			BitFieldDataType nonPackedBitfieldDt = (BitFieldDataType) nonPackedDtc.getDataType();
			if (bitfieldDt.getBitOffset() != nonPackedBitfieldDt.getBitOffset() ||
				bitfieldDt.getBitSize() != nonPackedBitfieldDt.getBitSize()) {
				return false;
			}
		}
		return true;
	}

	@Override
	int getOffset() {
		return memberOffset;
	}

	@Override
	void setOffset(int offset) {
		memberOffset = offset;
	}

	@Override
	int getLength() {
		if (memberDataType instanceof BitFieldDataType) {
			// FIXME: This assumption interferes with pack(1) case for bitfields
			BitFieldDataType bitfield = (BitFieldDataType) memberDataType;
			return bitfield.getBaseTypeSize();
		}
		return memberDataType != null ? memberDataType.getLength() : memberLength;
	}

	private void initializeContainer() {
		if (!(memberDataType instanceof Composite)) {
			throw new AssertException("Root must resolve to a composite type");
		}
		if (memberDataType instanceof Structure) {
			memberType = MemberType.STRUCTURE;
			structureMemberOffsetMap = new TreeMap<>();
			structureMemberRangeMap = new RangeMap(-1);
			// allow padding size to use pointer-size and smaller by default
			largestPrimitiveSize = memberDataType.getDataOrganization().getPointerSize();
			hasPadding = false;
			unionMemberList = null;
		}
		else {
			if (isClass) {
				throw new AssertException();
			}
			memberType = MemberType.UNION;
			unionMemberList = new ArrayList<>();
			structureMemberOffsetMap = null;
			structureMemberRangeMap = null;
		}
		memberLength = 0; // compositeMemberLength is preserved
	}

	/**
	 * Determine if this member is a container
	 * @return true if container, else false
	 */
	@Override
	boolean isContainer() {
		return memberType != MemberType.MEMBER; // memberDataTypeName == null;
	}

	/**
	 * Determine if this member is a union container
	 * @return true if union container, else false
	 */
	@Override
	boolean isUnionContainer() {
		return unionMemberList != null;
	}

	/**
	 * Determine if this member is a structure container
	 * @return true if structure container, else false
	 */
	@Override
	boolean isStructureContainer() {
		return structureMemberOffsetMap != null;
	}

	@Override
	boolean isBitFieldMember() {
		return memberDataType instanceof PdbBitField;
	}

	@Override
	boolean isSingleBitFieldMember() {
		return isBitFieldMember() && bitFieldGroup == null;
	}

	private int getDepth() {
		int depth = 0;
		DefaultCompositeMember p = parent;
		while (p != null) {
			p = p.parent;
			++depth;
		}
		return depth;
	}

	@Override
	public String toString() {
		String type;
		if (isUnionContainer()) {
			type = "Union";
		}
		else if (isStructureContainer()) {
			type = "Structure";
		}
		else if (isBitFieldMember()) {
			type = memberDataType.toString();
		}
		else {
			type = memberDataTypeName;
		}
		return "[CompositeMember: " + memberOffset + " " + memberName + " " + type + "]";
	}

	/**
	 * Attempt to add a child member to this composite hierarchy
	 * @param child PDB data-type member record
	 * @param monitor task monitor
	 * @return true if child data type resolved and it was successfully added to composite hierarchy,
	 * false if unable to resolve member's data-type or other error occurred.
	 * NOTE: there may be complex hierarchies not yet handled.
	 * @throws CancelledException if operation cancelled
	 * @throws DataTypeDependencyException if child's datatype can not be resolved.
	 * It may be possible to skip and continue with next child.
	 */
	private boolean addMember(PdbMember child, TaskMonitor monitor)
			throws CancelledException, DataTypeDependencyException {

		if (!isContainer()) {
			throw new AssertException("addMember only permitted on root members");
		}
		if (!(memberDataType instanceof Composite)) {
			throw new AssertException();
		}
		return addMember(
			new DefaultCompositeMember(child, dataTypeManager, errorConsumer, monitor));
	}

	private CategoryPath getChildCategoryPath() {
		return new CategoryPath(memberDataType.getCategoryPath(), getDataTypeName());
	}

	private String getOutermostDataTypeName() {
		if (parent != null) {
			return parent.getOutermostDataTypeName();
		}
		return getDataTypeName();
	}

	private boolean transformIntoUnionContainer() {

		if (parent == null) {
			throw new AssertException();
		}

		if (getDepth() >= MAX_CONSTRUCTION_DEPTH) {
			Msg.error(this, "PDB composite reconstruction exceeded maximum allowed depth: " +
				getOutermostDataTypeName());
			return false;
		}

		// Remove siblings from parent whose offsets are greater
		List<CompositeMember> elderSiblings = kidnapElderSiblingsFromParentStructure();

		DefaultCompositeMember memberCopy = new DefaultCompositeMember(this);
		memberCopy.memberOffset = 0;

		CategoryPath tempCategoryPath = parent.getDataType().getCategoryPath();
		String tempName = allocateTemporaryContainerName("union");

		Union nestedUnion = new UnionDataType(tempCategoryPath, tempName, dataTypeManager);

		nestedUnion.add(memberDataType, memberName, memberCopy.getMemberComment());

		String oldName = memberName;
		memberName = tempName;
		memberDataType = nestedUnion;
		memberIsZeroLengthArray = false;
		memberDataTypeName = null; // signifies a container
		initializeContainer();

		unionMemberList.add(memberCopy);
		memberCopy.parent = this;

		if (!elderSiblings.isEmpty()) {
			if (!memberCopy.transformIntoStructureContainer()) {
				return false;
			}
			for (CompositeMember sibling : elderSiblings) {
				sibling.setOffset(sibling.getOffset() - memberOffset);
				if (!sibling.addToStructure(memberCopy)) {
					return false;
				}
			}
		}

		if (parent != null) {
			parent.memberChanged(oldName, this);
		}

		return true;
	}

	@Override
	boolean addToStructure(DefaultCompositeMember structure) {
		return structure.addStructureMember(this);
	}

	boolean transformIntoStructureContainer() {

		if (parent == null) {
			throw new AssertException();
		}

		if (getDepth() >= MAX_CONSTRUCTION_DEPTH) {
			Msg.error(this, "PDB composite reconstruction exceeded maximum allowed depth: " +
				getOutermostDataTypeName());
			return false;
		}

		DefaultCompositeMember memberCopy = new DefaultCompositeMember(this);

		CategoryPath tempCategoryPath = parent.getDataType().getCategoryPath();
		String tempName = allocateTemporaryContainerName("struct");

		Structure nestedStructure =
			new StructureDataType(tempCategoryPath, tempName, 0, dataTypeManager);

		memberName = tempName;
		memberOffset = 0;
		memberDataType = nestedStructure;
		memberIsZeroLengthArray = false;
		memberDataTypeName = null; // signifies a container
		initializeContainer();

		if (parent != null) {
			parent.memberChanged(memberCopy.memberName, this);
		}

		return addStructureMember(memberCopy);
	}

	private String getMemberComment() {
		if (memberComment == null && !memberIsZeroLengthArray) {
			return null;
		}
		StringBuilder buf = new StringBuilder();
		if (memberComment != null) {
			buf.append(memberComment);
		}
		if (memberIsZeroLengthArray) {
			if (buf.length() != 0) {
				buf.append("; ");
			}
			buf.append("warning: zero length array forced to have one element");
		}
		return buf.toString();
	}

	private int getMinimumPackedStructureLength() {
		if (!isStructureContainer()) {
			throw new IllegalStateException();
		}

		Entry<Integer, CompositeMember> lastEntry = structureMemberOffsetMap.lastEntry();
		if (lastEntry == null) {
			return 0;
		}

		int lastOffset = lastEntry.getKey();
		CompositeMember lastMember = lastEntry.getValue();
		return lastOffset + lastMember.getLength();
	}

	/**
	 * Insert minimal padding into structure prior to the addition of a component such that packing
	 * will allow component to be placed at intended offset.
	 * @param nextComponentOffset 
	 * @param dt 
	 */
	private void insertMinimalStructurePadding(int nextComponentOffset, DataType dt) {

		if (!isStructureContainer()) {
			throw new IllegalStateException();
		}

		int structLen = getMinimumPackedStructureLength();
		if (nextComponentOffset <= structLen) {
			return;
		}

		if (dt instanceof AbstractIntegerDataType) {
			largestPrimitiveSize = Math.max(largestPrimitiveSize, dt.getLength());
		}

		Structure struct = (Structure) memberDataType;

		int fillSpace = nextComponentOffset - structLen;
		while (fillSpace > 0) {

			int alignedOffset = DataOrganizationImpl.getAlignedOffset(dt.getAlignment(), structLen);
			if (alignedOffset == nextComponentOffset) {
				return;
			}

			DataType paddingDt = getPaddingDataType(nextComponentOffset, structLen);
			if (paddingDt == null) {
				return;
			}

			int paddingOffset =
				DataOrganizationImpl.getAlignedOffset(paddingDt.getAlignment(), structLen);
			struct.insertAtOffset(paddingOffset, paddingDt, -1, PADDING_COMPONENT_NAME, null);
			hasPadding = true;

			structLen = struct.getLength();
			fillSpace = nextComponentOffset - structLen;
		}
	}

	private DataType getPaddingDataType(int nextComponentOffset, int structLen) {

		if (largestPrimitiveSize <= 1) {
			return new CharDataType(dataTypeManager);
		}

		for (int paddingSize = largestPrimitiveSize; paddingSize > 1; --paddingSize) {
			DataType paddingDt =
				AbstractIntegerDataType.getSignedDataType(paddingSize, dataTypeManager);
			int alignedOffset =
				DataOrganizationImpl.getAlignedOffset(paddingDt.getAlignment(), structLen);
			if ((alignedOffset + paddingSize) <= nextComponentOffset) {
				return paddingDt;
			}
		}
		return new CharDataType(dataTypeManager);
	}

	/**
	 * Insert a structure bitfield without creating additional undefined padding
	 * components (i.e., keep to minimal storage size).
	 * @param struct structure
	 * @param memberOffset byte offset within structure
	 * @param memberName member name
	 * @param bitfieldDt bitfield datatype with minimal storage
	 * @param comment member comment
	 * @return newly inserted structure bitfield component
	 */
	private static DataTypeComponent insertMinimalStructureBitfield(Structure struct,
			int memberOffset, String memberName, PdbBitField bitfieldDt, String comment) {
		try {
			int baseOffsetAdjustment = bitfieldDt.getBitOffsetWithinBase() / 8;
			return struct.insertBitFieldAt(memberOffset + baseOffsetAdjustment,
				bitfieldDt.getStorageSize(), bitfieldDt.getBitOffset(),
				bitfieldDt.getBaseDataType(), bitfieldDt.getDeclaredBitSize(), memberName, comment);
		}
		catch (InvalidDataTypeException e) {
			throw new RuntimeException(e); // unexpected
		}
	}

	private boolean isRelatedBitField(int conflictOffset, DefaultCompositeMember newMember) {
		if (!isContainer()) {
			throw new AssertException();
		}
		if (conflictOffset < 0 || !newMember.isBitFieldMember()) {
			return false;
		}

		CompositeMember conflictMember = structureMemberOffsetMap.get(conflictOffset);
		return isRelatedBitField(conflictMember, newMember);
	}

	private boolean isRelatedBitField(CompositeMember existingMember,
			DefaultCompositeMember newMember) {

		if (!newMember.isBitFieldMember()) {
			return false;
		}

		if (existingMember == null) {
			return false;
		}

		if (isUnionContainer() && existingMember.isStructureContainer()) {
			DefaultCompositeMember structureMember = (DefaultCompositeMember) existingMember;
			return structureMember.isRelatedBitField(newMember.getOffset(), newMember);
		}

		if (!existingMember.isBitFieldMember() ||
			existingMember.getOffset() != newMember.getOffset() ||
			existingMember.getLength() != newMember.getLength()) {
			return false;
		}

		// Assume grouped bit-fields are added sequentially
		// Unioned bit-fields can not be reliably differentiated from those contained
		// within a structure

		Composite composite = (Composite) memberDataType;
		DataTypeComponent component = composite.getComponent(composite.getNumComponents() - 1);

		DataType dataType = component.getDataType();
		if (!(dataType instanceof BitFieldDataType) && !(dataType == DataType.DEFAULT)) {
			return false;
		}

		PdbBitField newBitField = (PdbBitField) newMember.getDataType();

		// NOTE: assumes little-endian bitfield packing
		// TODO: Add support for big-endian

		int consumed;
		if (existingMember instanceof BitFieldGroupCompositeMember) {
			consumed = ((BitFieldGroupCompositeMember) existingMember).getConsumedBits();
		}
		else {
			DefaultCompositeMember m = (DefaultCompositeMember) existingMember;
			BitFieldDataType conflictBitField = (BitFieldDataType) m.memberDataType;
			consumed = conflictBitField.getBitOffset() + conflictBitField.getBitSize();
		}

		int relativeBitOffset = 0;
		int bitOffsetWithinBase = newBitField.getBitOffsetWithinBase();
		if (bitOffsetWithinBase >= 0) {
			relativeBitOffset = bitOffsetWithinBase - consumed;
			if (relativeBitOffset < 0) {
				return false; // overlap
			}
		}

		// ensure that bit fields can get packed together
		return (consumed + relativeBitOffset + newBitField.getBitSize()) <= (8 *
			newBitField.getBaseTypeSize());
	}

	private DefaultCompositeMember getPaddingBitField(BitFieldGroupCompositeMember bfGroup,
			DefaultCompositeMember nextBitFieldMember) throws InvalidDataTypeException {

		if (!nextBitFieldMember.isBitFieldMember()) {
			throw new AssertException();
		}

		// NOTE: assumes little-endian bitfield packing
		// TODO: Add support for big-endian

		int nextBitOffset = 0;
		if (bfGroup != null) {
			nextBitOffset = bfGroup.getConsumedBits();
		}

		PdbBitField nextBitfieldDt = (PdbBitField) nextBitFieldMember.getDataType();

		int bitOffsetWithinBase = nextBitfieldDt.getBitOffsetWithinBase();
		if (bitOffsetWithinBase > nextBitOffset) {
			// if bit-offset was specified padding may be required

			int fillerBitSize = bitOffsetWithinBase - nextBitOffset;
			// bitOffset = bitOffset; will need adjustment for big-endian

			return new DefaultCompositeMember(nextBitFieldMember.memberOffset,
				nextBitfieldDt.getBaseDataType(), fillerBitSize, nextBitOffset);
		}
		return null;
	}

	private boolean addStructureMember(DefaultCompositeMember member) {
		try {
			// check for conflict within structure container deferred
			int conflictOffset = structureMemberRangeMap.getValue(member.memberOffset);
			if (conflictOffset < 0) {

				DefaultCompositeMember deferredBitFieldMember = null;

				if (member.isBitFieldMember()) {

					PdbBitField bitfieldDt = (PdbBitField) member.memberDataType;

					int bitOffset = bitfieldDt.getBitOffsetWithinBase();
					DefaultCompositeMember padding = getPaddingBitField(null, member);
					if (padding != null) {
						deferredBitFieldMember = member;
						member = padding;
						bitfieldDt = (PdbBitField) member.memberDataType;
						bitOffset = bitfieldDt.getBitOffsetWithinBase();
					}
					else if (bitOffset < 0) {
						// TODO: assumes little-endian, add support for big-endian
						bitOffset = 0;
					}
					insertMinimalStructurePadding(member.memberOffset,
						bitfieldDt.getBaseDataType());
					insertMinimalStructureBitfield((Structure) memberDataType, member.memberOffset,
						member.getName(), bitfieldDt, member.getMemberComment());
				}
				else {
					insertMinimalStructurePadding(member.memberOffset, member.memberDataType);
					((Structure) memberDataType).insertAtOffset(member.memberOffset,
						member.memberDataType, member.getLength(), member.memberName,
						member.getMemberComment());
				}

				member.parent = this;
				structureMemberOffsetMap.put(member.memberOffset, member);
				structureMemberRangeMap.paintRange(member.memberOffset,
					member.memberOffset + member.getLength() - 1, member.memberOffset);

				if (deferredBitFieldMember != null) {
					return addStructureMember(deferredBitFieldMember);
				}

				if (parent != null) {
					parent.sizeChanged(this);
				}

				return true;
			}

			CompositeMember conflictMember = structureMemberOffsetMap.get(conflictOffset);

			if (isRelatedBitField(conflictOffset, member)) {

				BitFieldGroupCompositeMember bfGroup;
				if (conflictMember instanceof BitFieldGroupCompositeMember) {
					bfGroup = (BitFieldGroupCompositeMember) conflictMember;
				}
				else {
					bfGroup = new BitFieldGroupCompositeMember();
					bfGroup.addToGroup(conflictMember);
					structureMemberOffsetMap.put(bfGroup.getOffset(), bfGroup);
				}

				DefaultCompositeMember deferredBitFieldMember = null;

				PdbBitField bitfieldDt = (PdbBitField) member.memberDataType;

				int bitOffset = bitfieldDt.getBitOffsetWithinBase();
				DefaultCompositeMember padding = getPaddingBitField(bfGroup, member);
				if (padding != null) {
					deferredBitFieldMember = member;
					member = padding;
					bitfieldDt = (PdbBitField) member.memberDataType;
					bitOffset = bitfieldDt.getBitOffsetWithinBase();
				}
				else if (bitOffset < 0) {
					// TODO: assumes little-endian, add support for big-endian
					bitOffset = bfGroup.getConsumedBits();
				}

				// Error if member and conflict member do not have same offset and type length.
				// This assumes bit-field packing does not mix type size together as does gcc
				bfGroup.addToGroup(member);

				insertMinimalStructureBitfield((Structure) memberDataType, member.memberOffset,
					member.getName(), bitfieldDt, member.getMemberComment());

				member.parent = this;

				if (deferredBitFieldMember != null) {
					return addStructureMember(deferredBitFieldMember);
				}

				return true;
			}

			// adjust this member's offset for addition to container
			member.setOffset(member.getOffset() - conflictMember.getOffset());

			return conflictMember.addMember(member);
		}
		catch (InvalidDataTypeException e) {
			Msg.error(this, "PDB failed to add bitfield: " + e.getMessage());
			return false;
		}
	}

	private boolean addUnionMember(DefaultCompositeMember member) {

		if (member.memberOffset == 0) {

			if (unionMemberList.size() != 0 && member.isBitFieldMember()) {
				CompositeMember lastUnionMember = unionMemberList.get(unionMemberList.size() - 1);
				if (isRelatedBitField(lastUnionMember, member)) {
					if (lastUnionMember.isSingleBitFieldMember() &&
						!((DefaultCompositeMember) lastUnionMember)
								.transformIntoStructureContainer()) {
						return false;
					}
					return lastUnionMember.addMember(member);
				}
			}

			unionMemberList.add(member);
			member.parent = this;
			((Union) memberDataType).add(member.memberDataType, member.memberName,
				member.getMemberComment());
			if (parent != null) {
				parent.sizeChanged(this);
			}
			if (member.memberIsZeroLengthArray && !member.transformIntoStructureContainer()) {
				return false;
			}
			return true;
		}

		int unionMemberCount = unionMemberList.size();
		CompositeMember lastUnionMember =
			unionMemberCount == 0 ? null : unionMemberList.get(unionMemberCount - 1);

		// NOTE: It is assumed that offset will always be ascending and not reach back to union
		// members before the last one

		if (lastUnionMember == null) {
			member.parent = this;
			if (!member.transformIntoStructureContainer()) {
				return false;
			}
			((Union) memberDataType).add(member.memberDataType, member.memberName, null);
			unionMemberList.add(member);
			if (parent != null) {
				parent.sizeChanged(this);
			}
			return true;
		}

		if (lastUnionMember.isStructureContainer() &&
			member.memberOffset >= lastUnionMember.getOffset()) {

			DefaultCompositeMember struct = (DefaultCompositeMember) lastUnionMember;
			if (struct.isRelatedBitField(member.memberOffset - lastUnionMember.getOffset(),
				member)) {
				// pack bit-field into member structure with related bit field(s)
				member.memberOffset -= lastUnionMember.getOffset();
				return lastUnionMember.addMember(member);
			}
		}

		if (member.memberOffset >= (lastUnionMember.getOffset() + lastUnionMember.getLength())) {
			// NOTE: Placement is rather speculative - assume structure is required
			// TODO: watch out for nested union
			member.memberOffset -= lastUnionMember.getOffset();
			return lastUnionMember.addMember(member);
		}

		// NOTE: union must be forced into structure transformation
		if (lastUnionMember instanceof DefaultCompositeMember) {
			DefaultCompositeMember m = (DefaultCompositeMember) lastUnionMember;
			if (m.isUnionContainer() && !m.transformIntoStructureContainer()) {
				return false;
			}
		}
		return lastUnionMember.addMember(member);
	}

	private void sizeChanged(DefaultCompositeMember pdbMember) {
		if (structureMemberRangeMap != null) {
			structureMemberRangeMap.paintRange(pdbMember.memberOffset,
				pdbMember.memberOffset + pdbMember.getLength() - 1, pdbMember.memberOffset);
		}
		if (parent != null) {
			parent.sizeChanged(this);
		}
	}

	/**
	 * Replace existing member with newContainerMember
	 * @param fieldName name of existing field (used to locate union member)
	 * @param newContainerMember container replacement member
	 */
	private void memberChanged(String fieldName, DefaultCompositeMember newContainerMember) {
		if (!newContainerMember.isContainer()) {
			throw new AssertException();
		}
		if (isUnionContainer()) {
			Union union = (Union) memberDataType;
			int count = union.getNumComponents();
			for (int i = 0; i < count; i++) {
				DataTypeComponent component = union.getComponent(i);
				if (fieldName.equals(component.getFieldName())) {
					union.delete(i);
					union.insert(i, newContainerMember.getDataType(),
						newContainerMember.getLength(), newContainerMember.memberName, null);
					break;
				}
			}
		}
		else if (isStructureContainer()) {
			Structure struct = (Structure) memberDataType;
			// TODO: complicated by bitfields where multiple components may occupy same byte
			struct.deleteAtOffset(newContainerMember.getOffset());
			struct.insertAtOffset(newContainerMember.getOffset(), newContainerMember.getDataType(),
				newContainerMember.getLength());
			structureMemberOffsetMap.put(newContainerMember.getOffset(), newContainerMember);
		}
	}

	private void memberNameChanged(String oldFieldName, String newFieldName) {
		if (isContainer()) {
			Composite composite = (Composite) memberDataType;
			int count = composite.getNumComponents();
			for (int i = 0; i < count; i++) {
				DataTypeComponent component = composite.getComponent(i);
				if (oldFieldName.equals(component.getFieldName())) {
					try {
						component.setFieldName(newFieldName);
					}
					catch (DuplicateNameException e) {
						Msg.error(this, "Failed to rename temporary component name: " +
							getDataTypeName() + "." + oldFieldName + " -> " + newFieldName);
					}
					break;
				}
			}
		}
	}

	private int getOrdinal(String fieldName) throws NotFoundException {
		if (!isContainer()) {
			throw new AssertException();
		}
		Composite composite = (Composite) memberDataType;
		int count = composite.getNumComponents();
		for (int i = 0; i < count; i++) {
			DataTypeComponent component = composite.getComponent(i);
			if (fieldName.equals(component.getFieldName())) {
				return i;
			}
		}
		throw new NotFoundException();
	}

	@Override
	boolean addMember(DefaultCompositeMember member) {

		if (member.memberDataType == null || member.memberDataType.getLength() <= 0) {
			Msg.debug(this, "Failed to resolve member datatype for '" + getDataTypeName() + "': " +
				member.getDataTypeName());
			return false;
		}

		if (!isContainer()) {
			if (member.memberOffset != 0) {
				if (!transformIntoStructureContainer()) {
					return false;
				}
			}
			else {
				if (!transformIntoUnionContainer()) {
					return false;
				}
			}
		}

		if (isUnionContainer()) {
			return addUnionMember(member);
		}
		return addStructureMember(member);
	}

	/**
	 * This method facilitates the removal and collection of all siblings of this
	 * member from its parent container.  Only those siblings whose offset is greater
	 * than this member's offset will be included.  The use of this method is necessary when
	 * a member sequence has been added to a structure container and it is later decided to
	 * push this member and its siblings into a new sub-composite.  Before they can be
	 * added to the new container they must be removed from their current container
	 * using this method.
	 * @return list of sibling structure members removed from parent
	 */
	private List<CompositeMember> kidnapElderSiblingsFromParentStructure() {

		List<CompositeMember> list = new ArrayList<>();
		if (parent == null || !parent.isStructureContainer()) {
			return list;
		}

		Structure parentStruct = (Structure) parent.memberDataType;

		// structureMemberOffsetMap may contain BitFieldGroupCompositeMember which corresponds
		// to multiple components within the actual parent structure so there is not a one-to-one
		// relationship.

		for (int offset : parent.structureMemberOffsetMap.keySet()) {
			CompositeMember m = parent.structureMemberOffsetMap.get(offset);
			if (m.getOffset() >= memberOffset && m != this) {
				list.add(m);
			}
		}

		// must remove sibling bit fields at same offset but must leave
		// first one behind to facilitate subsequent component swap.
		boolean skipIfEqual = true;
		int truncateOrdinal = -1;
		for (DataTypeComponent component : parentStruct.getComponents()) {
			int offset = component.getOffset();
			if (offset >= memberOffset) {
				if (skipIfEqual && offset == memberOffset) {
					skipIfEqual = false;
				}
				else {
					if (truncateOrdinal < 0) {
						truncateOrdinal = component.getOrdinal();
					}
					parent.structureMemberOffsetMap.remove(offset);
				}
			}
		}
		if (truncateOrdinal >= 0) {
			while (parentStruct.getNumComponents() > truncateOrdinal) {
				parentStruct.delete(truncateOrdinal);
			}
		}

		parent.structureMemberRangeMap.paintRange(memberOffset + getLength(), parent.getLength(),
			-1);

		return list;
	}

	/**
	 * Buildup an empty composite by applying datatype composite members.
	 * Only those children with a kind of "Member" will be processed.
	 * @param composite empty composite to which members will be added
	 * @param isClass true if composite corresponds to a Class structure, else false
	 * @param preferredCompositeSize preferred size of composite, <= 0 indicates unknown
	 * @param members list of composite members
	 * @param errorConsumer error consumer (may be null)
	 * @param monitor task monitor
	 * @return true if members successfully added to composite
	 * @throws CancelledException if monitor is cancelled
	 */
	public static boolean applyDataTypeMembers(Composite composite, boolean isClass,
			int preferredCompositeSize, List<? extends PdbMember> members,
			Consumer<String> errorConsumer, TaskMonitor monitor) throws CancelledException {

		Composite editComposite = composite;

		DefaultCompositeMember rootMember =
			new DefaultCompositeMember(isClass, editComposite, errorConsumer);

		for (PdbMember m : members) {
			monitor.checkCancelled();
			try {
				if (!rootMember.addMember(m, monitor)) {
					return false;
				}
			}
			catch (DataTypeDependencyException e) {
				String message = "Failed to resolve datatype dependency for " +
					composite.getPathName() + ": " + m.getDataTypeName();
				if (errorConsumer != null) {
					errorConsumer.accept(message);
				}
				else {
					Msg.error(DefaultCompositeMember.class, message);
				}
			}
		}

		rootMember.finalizeDataType(preferredCompositeSize);
		return true;
	}

	void setBitFieldGroup(BitFieldGroupCompositeMember group) {
		bitFieldGroup = group;
	}

	private static enum MemberType {

		//@formatter:off
		STRUCTURE,
		UNION,
		MEMBER;
		//@formatter:on

	}

}
