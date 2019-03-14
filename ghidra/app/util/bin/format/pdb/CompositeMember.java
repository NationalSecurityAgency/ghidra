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

import ghidra.app.util.bin.format.pdb.PdbParserNEW.WrappedDataType;
import ghidra.program.model.data.*;
import ghidra.util.*;
import ghidra.util.datastruct.RangeMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.XmlTreeNode;

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
class CompositeMember {

	private static int MAX_CONSTRUCTION_DEPTH = 20;

	private DataTypeManager dataTypeManager;

	private CompositeMember parent; // parent container (null if this is root container)

	private String memberName; // null if this is a root container
	private String memberDataTypeName; // null if this is a container
	private int memberOffset; // member offset relative to start of parent container
	private String memberKind; // PDB defined kind of data type (e.g., Structure, Union)
	private int memberLength; // container members have 0 length (rely on memberDataType)

	private DataType memberDataType;
	private boolean memberIsZeroLengthArray;

	private DataTypeResolver memberDataTypeResolver;

	// Structure container data
	private Map<Integer, CompositeMember> structureMemberOffsetMap;
	private RangeMap structureMemberRangeMap;

	// Union container data
	private List<CompositeMember> unionMemberList;
	private boolean isBitFieldUnion;
	private int bitFieldUnionLength;

	private static long nextTemporaryValue;

	private static synchronized String allocateTemporaryContainerName() {
		return "_tmp_" + nextTemporaryValue++;
	}

	/**
	 * Construct the outermost root container member for a new composite data-type.
	 * @param dataTypeResolver data-type resolver
	 * @param monitor task monitor
	 * @throws CancelledException if task is cancelled
	 */
	CompositeMember(DataTypeResolver dataTypeResolver, DataTypeManager dataTypeManager)
			throws CancelledException {
		memberOffset = -1;
		memberDataTypeResolver = dataTypeResolver;
		this.dataTypeManager = dataTypeManager;
		resolve();
	}

	/**
	 * Construct a new composite member from a PDB data-type member record.
	 * @param member PDB member record
	 * @param dataTypeResolver data-type resolver
	 * @param monitor task monitor
	 * @throws CancelledException if task is cancelled
	 */
	private CompositeMember(PdbMember member, DataTypeResolver dataTypeResolver,
			DataTypeManager dataTypeManager, TaskMonitor monitor) throws CancelledException {
		memberName = member.memberName;
		memberDataTypeName = member.memberDataTypeName;
		memberOffset = member.memberOffset;
		memberKind = member.memberKind;
		memberLength = member.memberLength;
		memberDataTypeResolver = dataTypeResolver;
		this.dataTypeManager = dataTypeManager;
		resolve();
	}

	/**
	 * Construct a new composite member by cloning an existing member.
	 * @param member composite member to be cloned
	 */
	private CompositeMember(CompositeMember member) {
		memberName = member.memberName;
		memberDataTypeName = member.memberDataTypeName;
		memberDataType = member.memberDataType;
		memberIsZeroLengthArray = member.memberIsZeroLengthArray;
		memberOffset = member.memberOffset;
		memberKind = member.memberKind;
		memberLength = member.memberLength;
		memberDataTypeResolver = member.memberDataTypeResolver;
		dataTypeManager = member.dataTypeManager;
		structureMemberOffsetMap = member.structureMemberOffsetMap;
		structureMemberRangeMap = member.structureMemberRangeMap;
		unionMemberList = member.unionMemberList;
		isBitFieldUnion = member.isBitFieldUnion;
		bitFieldUnionLength = member.bitFieldUnionLength;
	}

	/**
	 * Get member name to be used within parent composite definition
	 * @return member name or null if this is root container
	 */
	String getName() {
		return memberName;
	}

	/**
	 * Get the PDB defined KIND designator for this member (e.g., Structure, Union)
	 * @return PDB defined KIND of member
	 */
	String getKind() {
		return memberKind;
	}

	/**
	 * Get the data type name associated with this member.  Anonymous inner composite
	 * types will utilize a generated named based upon its parent type name and the
	 * offset at which it occurs within its parent.
	 * @return data type name associated with this member
	 */
	String getDataTypeName() {
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

	/**
	 * Due to the dynamic restructuring of data type containers, this method should be invoked
	 * on the root container prior to adding or applying the associated data type to the program.  
	 * This method will appropriately rename and categorize associated anonymous structures and 
	 * unions to reflect the final organization and check if internal alignment should be enabled.
	 * @param preferredSize preferred size of composite if known, else <= 0 if unknown
	 */
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
			if (lastMember != null && lastMember.memberIsZeroLengthArray) {
				// transform last member into flexible array
				Structure struct = (Structure) memberDataType;
				Array array = (Array) lastMember.getDataType();
				struct.setFlexibleArrayComponent(array.getDataType(), lastMember.getName(), null);
				struct.delete(struct.getNumComponents() - 1);
			}
		}
		else if (isUnionContainer()) {
			if (isBitFieldUnionContainer()) {
				updateContainerNameAndCategoryPath("bitfield");
			}
			else {
				updateContainerNameAndCategoryPath("u");
				for (CompositeMember member : unionMemberList) {
					member.finalizeDataType(0);
				}
			}
		}
		if (testContainerAlignment(preferredSize)) {
			((Composite) memberDataType).setInternallyAligned(true);
		}
	}

	/**
	 * Determine is a container type should enable alignment.
	 * @param preferredSize preferred size of composite if known, else <= 0 if unknown
	 * @return true if internal structure alignment should be enabled, else false
	 */
	private boolean testContainerAlignment(int preferredSize) {
		Composite copy = (Composite) memberDataType.copy(dataTypeManager);
		copy.setInternallyAligned(true);
		if (preferredSize <= 0) {
			// assume anonymous composites are aligned if size does not change
			return copy.getLength() == memberDataType.getLength();
		}
		// use alignment if length matches preferredSize
		return copy.getLength() == preferredSize;
	}

	/**
	 * Get the offset of this member relative to the start of its parent container.
	 * @return relative member offset or -1 for root container
	 */
	int getOffset() {
		return memberOffset;
	}

	/**
	 * Get the data type length associated with this member.  Container members data-type
	 * length may continue to grow as additional members are added.
	 * @return data type associated with this member.
	 */
	int getLength() {
		return memberDataType != null ? memberDataType.getLength() : memberLength;
	}

	private void resolve() throws CancelledException {
		WrappedDataType wrappedDataType = memberDataTypeResolver.resolveDataType(this);
		if (wrappedDataType != null) {
			memberDataType = wrappedDataType.dataType.clone(dataTypeManager);
			memberIsZeroLengthArray = wrappedDataType.isZeroLengthArray;
		}
		if (isContainer()) {
			initializeContainer();
		}
	}

	private void initializeContainer() {
		if (!(memberDataType instanceof Composite)) {
			throw new AssertException("Root must resolve to a composite type");
		}
		if (memberDataType instanceof Structure) {
			memberKind = PdbParserNEW.STRUCTURE_KIND;
			structureMemberOffsetMap = new TreeMap<>();
			structureMemberRangeMap = new RangeMap(-1);
			unionMemberList = null;
		}
		else {
			memberKind = PdbParserNEW.UNION_KIND;
			unionMemberList = new ArrayList<>();
			structureMemberOffsetMap = null;
			structureMemberRangeMap = null;
		}
		isBitFieldUnion = false;
		bitFieldUnionLength = 0;
		memberLength = 0; // compositeMemberLength is preserved
	}

	/**
	 * Determine if this member is a container
	 * @return true if container, else false
	 */
	boolean isContainer() {
		return memberDataTypeName == null;
	}

	/**
	 * Determine if this member is a union container
	 * @return true if union container, else false
	 */
	boolean isUnionContainer() {
		return unionMemberList != null;
	}

	/**
	 * Determine if this member is a structure container
	 * @return true if structure container, else false
	 */
	boolean isStructureContainer() {
		return structureMemberOffsetMap != null;
	}

	/**
	 * Determine if this member is a bit-field member
	 * @return true if bit-field member, else false
	 */
	boolean isBitFieldMember() {
		if (memberName == null || memberLength == 0) {
			return false;
		}
		int colonPos = memberName.indexOf(':');
		if (colonPos == -1) {
			return false;
		}
		int nextColonPos = memberName.indexOf(':', colonPos + 1);
		if (nextColonPos != -1) {
			return false;
		}
		String[] split = memberName.split(":");
		try {
			int bitIndex = XmlUtilities.parseInt(split[1]);
			if (bitIndex < 0) {
				return false;
			}
		}
		catch (Exception e) {
			return false;
		}
		return true;
	}

	private boolean isBitFieldUnionContainer() {
		if (!isUnionContainer() || unionMemberList.size() < 2) {
			return false;
		}
		CompositeMember member0 = unionMemberList.get(0);
		CompositeMember member1 = unionMemberList.get(1);
		return member0.isBitFieldMember() && member0.isCompanionBitField(member1);
	}

	private int getDepth() {
		int depth = 0;
		CompositeMember p = parent;
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
			type = PdbParserNEW.UNION_KIND;
		}
		else if (isStructureContainer()) {
			type = PdbParserNEW.STRUCTURE_KIND;
		}
		else {
			type = memberDataTypeName;
		}
		return "[CompositeMember: " + memberOffset + " " + memberName + " " + type + "]";
	}

	/**
	 * <code>DataTypeResolver</code> provides the ability to resolve a member's data-type 
	 * at the time of construction.
	 */
	interface DataTypeResolver {
		/**
		 * Find the specified member's data type based upon its' data-type name
		 * @param member composite member to be resolved
		 * @return data-type which corresponds to the specified member's data-type name or null
		 * if unable to resolve.
		 * @throws CancelledException if operation cancelled
		 */
		WrappedDataType resolveDataType(CompositeMember member) throws CancelledException;
	}

	/**
	 * Attempt to add a child member to this composite hierarchy
	 * @param child PDB data-type member record
	 * @param monitor task monitor
	 * @return true if child data type resolved and it was successfully added to composite hierarchy,
	 * false if unable to resolve member's data-type or other error occurred.
	 * NOTE: there may be complex hierarchies not yet handled.
	 * @throws CancelledException if operation cancelled
	 */
	boolean addMember(PdbMember child, TaskMonitor monitor) throws CancelledException {

		if (!isContainer()) {
			throw new AssertException("addMember only permitted on root members");
		}
		if (!(memberDataType instanceof Composite)) {
			throw new AssertException();
		}

		if (!child.memberKind.equals("Member")) {
			throw new AssertException();
		}

		return addMember(
			new CompositeMember(child, memberDataTypeResolver, dataTypeManager, monitor));
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

		CompositeMember memberCopy = new CompositeMember(this);
		memberCopy.memberOffset = 0;

		CategoryPath tempCategoryPath = parent.getDataType().getCategoryPath();
		String tempName = allocateTemporaryContainerName();

		Union nestedUnion = new UnionDataType(tempCategoryPath, tempName, dataTypeManager);

		nestedUnion.add(memberDataType, memberName, null);

		String oldName = memberName;
		memberName = tempName;
		memberDataType = nestedUnion;
		memberIsZeroLengthArray = false;
		memberDataTypeName = null; // signifies a container
		initializeContainer();

		unionMemberList.add(memberCopy);
		memberCopy.parent = this;

		if (!elderSiblings.isEmpty()) {
			memberCopy.transformIntoStructureContainer();
			for (CompositeMember sibling : elderSiblings) {
				sibling.memberOffset -= memberOffset;
				if (!memberCopy.addStructureMember(sibling)) {
					return false;
				}
			}
		}

		isBitFieldUnion = memberCopy.isBitFieldMember();
		if (isBitFieldUnion) {
			bitFieldUnionLength = memberCopy.memberLength; // bit field length is bit-length
		}

		if (parent != null) {
			parent.memberChanged(oldName, this);
		}

		return true;
	}

	private boolean transformIntoStructureContainer() {

		if (parent == null) {
			throw new AssertException();
		}

		if (getDepth() >= MAX_CONSTRUCTION_DEPTH) {
			Msg.error(this, "PDB composite reconstruction exceeded maximum allowed depth: " +
				getOutermostDataTypeName());
			return false;
		}

		CompositeMember memberCopy = new CompositeMember(this);
		memberCopy.memberOffset = 0;

		CategoryPath tempCategoryPath = parent.getDataType().getCategoryPath();
		String tempName = allocateTemporaryContainerName();

		Structure nestedStructure =
			new StructureDataType(tempCategoryPath, tempName, 0, dataTypeManager);

		nestedStructure.insertAtOffset(0, memberDataType, memberDataType.getLength(), memberName,
			getStructureMemberComment());

		String oldName = memberName;
		memberName = tempName;
		memberDataType = nestedStructure;
		memberIsZeroLengthArray = false;
		memberDataTypeName = null; // signifies a container
		initializeContainer();

		structureMemberRangeMap.paintRange(0, memberCopy.getLength() - 1, 0);
		structureMemberOffsetMap.put(0, memberCopy);
		memberCopy.parent = this;

		if (parent != null) {
			parent.memberChanged(oldName, this);
		}
		return true;
	}

	private String getStructureMemberComment() {
		if (memberIsZeroLengthArray) {
			return "warning: zero length array forced to have one element";
		}
		return null;
	}

	private boolean addStructureMember(CompositeMember member) {

		// check for conflict within structure container
		int conflictOffset = structureMemberRangeMap.getValue(member.memberOffset);
		if (conflictOffset < 0) {
			structureMemberOffsetMap.put(member.memberOffset, member);
			structureMemberRangeMap.paintRange(member.memberOffset,
				member.memberOffset + member.getLength() - 1, member.memberOffset);
			member.parent = this;
			((Structure) memberDataType).insertAtOffset(member.memberOffset, member.memberDataType,
				member.getLength(), member.memberName, member.getStructureMemberComment());
			if (parent != null) {
				parent.sizeChanged(this);
			}
			return true;
		}

		CompositeMember conflictMember = structureMemberOffsetMap.get(conflictOffset);

		// adjust this member for addition to container
		member.memberOffset -= conflictMember.memberOffset;

		return conflictMember.addMember(member);
	}

	private boolean addUnionMember(CompositeMember member) {

		if (member.memberOffset == 0) {
			if (isBitFieldUnion && !isCompanionBitField(member)) {
				// push this union into a new union
				transformIntoUnionContainer();
				return addUnionMember(member); // try again
			}

			if (!isBitFieldUnion && unionMemberList.size() != 0 && member.isBitFieldMember()) {
				CompositeMember lastUnionMember = unionMemberList.get(unionMemberList.size() - 1);
				if (lastUnionMember.isCompanionBitField(member)) {
					return lastUnionMember.addMember(member);
				}
			}

			unionMemberList.add(member);
			member.parent = this;
			((Union) memberDataType).add(member.memberDataType, member.memberName, null);
			if (isBitFieldUnion) {
				bitFieldUnionLength += member.memberLength;
			}
			if (parent != null) {
				parent.sizeChanged(this);
			}
			return true;
		}

		// find relevant union member for structure conversion
		for (CompositeMember unionMember : unionMemberList) {
			if ((member.isBitFieldMember() && unionMember.isCompanionBitField(member)) ||
				(!member.isBitFieldMember() &&
					member.memberOffset >= (unionMember.memberOffset + unionMember.getLength()))) {
				// NOTE: Placement is rather speculative - assume structure is required
				// TODO: watch out for nested union
				member.memberOffset -= unionMember.memberOffset;
				return unionMember.addMember(member);
			}
		}

		CompositeMember lastUnionMember = unionMemberList.get(unionMemberList.size() - 1);
		// NOTE: union must be forced into structure transformation
		if (lastUnionMember.isUnionContainer()) {
			if (!lastUnionMember.transformIntoStructureContainer()) {
				return false;
			}
		}
		return lastUnionMember.addMember(member);
	}

	private boolean isCompanionBitField(CompositeMember member) {
		if (!member.isBitFieldMember()) {
			return false;
		}
		if (isContainer()) {
			if (isBitFieldUnion) {
				if (unionMemberList.size() == 0 || member.memberOffset != 0) {
					return false;
				}
				if (!SystemUtilities.isEqual(unionMemberList.get(0).memberDataTypeName,
					member.memberDataTypeName)) {
					return false;
				}
				int combinedBitfieldLength = bitFieldUnionLength + member.memberLength;
				if (combinedBitfieldLength > (member.getDataType().getLength() * 8)) {
					return false;
				}
				return true;
			}
			//return member.memberOffset < getLength();
			return false;
		}
		if (!isBitFieldMember()) {
			return false;
		}
		if (memberOffset != member.memberOffset) {
			return false;
		}
		return SystemUtilities.isEqual(memberDataTypeName, member.memberDataTypeName);
	}

	private void sizeChanged(CompositeMember pdbMember) {
		if (structureMemberRangeMap != null) {
			structureMemberRangeMap.paintRange(pdbMember.memberOffset,
				pdbMember.memberOffset + pdbMember.getLength() - 1, pdbMember.memberOffset);
		}
		if (parent != null) {
			parent.sizeChanged(this);
		}
	}

	private void memberChanged(String fieldName, CompositeMember newMember) {
		if (isUnionContainer()) {
			Union union = (Union) memberDataType;
			int count = union.getNumComponents();
			for (int i = 0; i < count; i++) {
				DataTypeComponent component = union.getComponent(i);
				if (fieldName.equals(component.getFieldName())) {
					union.delete(i);
					union.insert(i, newMember.getDataType(), newMember.getLength(),
						newMember.memberName, null);
					break;
				}
			}
		}
		else if (isStructureContainer()) {
			Structure struct = (Structure) memberDataType;
			struct.replaceAtOffset(newMember.getOffset(), newMember.getDataType(),
				newMember.getLength(), newMember.getName(), null);
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

	private boolean addMember(CompositeMember member) {

		if (member.memberDataType == null || member.memberDataType.getLength() <= 0) {
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

		for (DataTypeComponent component : parentStruct.getComponents()) {
			if (component.getOffset() > memberOffset) {
				parentStruct.clearComponent(component.getOrdinal());
				CompositeMember member =
					parent.structureMemberOffsetMap.remove(component.getOffset());
				// could be a padding undefined that was never added to the structureMemberOffsetMap
				if (member != null) {
					list.add(member);
				}
				else if (component.getDataType() != DataType.DEFAULT) {
					// exceptions are unexpected 
					throw new AssertException("Data Type component parsing issues " +
						parentStruct.getName() + " kidnapping " + component.getFieldName());
				}
			}
		}
		parent.structureMemberRangeMap.paintRange(memberOffset + getLength(), parent.getLength(),
			-1);
		return list;
	}

	/**
	 * Buildup an empty composite by applying datatype composite members defined as 
	 * children of an PDB XML class or datatype node.  Only those children with a kind of 
	 * "Member" will be processed. 
	 * @param pdbParser PDB parser object
	 * @param composite empty composite to which members will be added
	 * @param preferredCompositeSize preferred size of composite, <= 0 indicates unknown
	 * @param compositeNode PDB XML class or datatype node whose children will be processed
	 * @param monitor task monitor
	 * @return true if members successfully added to composite
	 * @throws CancelledException if monitor is cancelled
	 */
	static boolean applyDataTypeMembers(PdbParserNEW pdbParser, Composite composite,
			int preferredCompositeSize, XmlTreeNode compositeNode, TaskMonitor monitor)
			throws CancelledException {

		Composite editComposite = composite;

		CompositeMember rootMember = new CompositeMember(
			member -> member.isContainer() ? new WrappedDataType(editComposite, false)
					: pdbParser.findDataType(member.getDataTypeName(), monitor),
			pdbParser.getProgramDataTypeManager());

		Iterator<XmlTreeNode> children = compositeNode.getChildren();
		while (children.hasNext()) {
			monitor.checkCanceled();
			XmlTreeNode child = children.next();
			PdbMember member = new PdbMember(child, monitor);
			if (member.memberKind.equals("Member")) {
				if (!rootMember.addMember(member, monitor)) {
					return false;
				}
			}
		}

		rootMember.finalizeDataType(preferredCompositeSize);
		return true;
	}

}
