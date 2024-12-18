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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.app.util.pdb.classtype.*;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Notional C++ Class Type. Much work has yet to be done with this class.  For instance, the plan
 * is to continue to break this class up into smaller self-contained classes.
 */
public class CppCompositeType {

	// Order matters for both base classes and members for class layout.  Members get offsets,
	//  which helps for those, but layout algorithms usually utilize order.
	private List<SyntacticBaseClass> syntacticBaseClasses;
	private List<LayoutBaseClass> layoutBaseClasses;
	private List<AbstractMember> myMembers;
	private List<Member> layoutMembers;
	private List<Member> layoutVftPtrMembers;
	private boolean isFinal;
	private ClassKey classKey;
	private String className; // String for now.
	private String mangledName;
	private int size;
	private CategoryPath baseCategoryPath;
	private SymbolPath symbolPath;
	private Composite composite;
	private CategoryPath categoryPath;

	private ObjectOrientedClassLayout classLayout = null;

	private List<ClassPdbMember> memberData;

	private boolean hasDirect;

	static String createDirectClassName(Composite composite) {
		return composite.getName() + "_direct";
	}

	static CategoryPath createDirectCategoryPath(CppCompositeType cppType) {
		return cppType.getBaseCategoryName(
			CppCompositeType.createDirectClassName(cppType.getComposite()));
	}

	/*
	 * Not certain, but think there should only be one Virtual Base Table for a given
	 * class (not counting those for its parents).  However, since VirtualBaseClass and
	 * IndirectVirtualBase class records both have an "offset" for (seemingly) where the
	 * virtual base table point can be located, then there is a chance that different
	 * records for a class could have different values.  This HashMap will is keyed by this
	 * offset, in case we see more than one.  Want to log the fact if more than one value is seen
	 * for a particular hierarchy level.
	 */
	private Map<Integer, PlaceholderVirtualBaseTable> placeholderVirtualBaseTables;

	//----------------------------------------------------------------------------------------------
	public CppCompositeType(CategoryPath baseCategoryPath, SymbolPath symbolPath,
			Composite composite, String mangledName) {
		Objects.requireNonNull(symbolPath, "symbolPath may not be null");
		Objects.requireNonNull(composite, "composite may not be null");
		syntacticBaseClasses = new ArrayList<>();
		layoutBaseClasses = new ArrayList<>();
		myMembers = new ArrayList<>();
		layoutMembers = new ArrayList<>();

		memberData = new ArrayList<>();
		layoutVftPtrMembers = new ArrayList<>();

		isFinal = false;
		classKey = ClassKey.UNKNOWN;
		this.baseCategoryPath = baseCategoryPath;
		this.symbolPath = symbolPath;
		this.composite = composite;
		placeholderVirtualBaseTables = new HashMap<>();
		categoryPath = new CategoryPath(composite.getCategoryPath(), composite.getName());
		this.mangledName = mangledName;
	}

	public static CppClassType createCppClassType(CategoryPath baseCategoryPath,
			SymbolPath symbolPath, Composite composite, String mangledName) {
		return new CppClassType(baseCategoryPath, symbolPath, composite, mangledName);
	}

	public static CppClassType createCppClassType(CategoryPath baseCategoryPath,
			SymbolPath symbolPath, Composite composite, String name, String mangledName, int size) {
		CppClassType cppType =
			new CppClassType(baseCategoryPath, symbolPath, composite, mangledName);
		cppType.setName(name);
		cppType.setSize(size);
		return cppType;
	}

	public static CppStructType createCppStructType(CategoryPath baseCategoryPath,
			SymbolPath symbolPath, Composite composite, String mangledName) {
		return new CppStructType(baseCategoryPath, symbolPath, composite, mangledName);
	}

	public static CppStructType createCppStructType(CategoryPath baseCategoryPath,
			SymbolPath symbolPath, Composite composite, String name, String mangledName, int size) {
		CppStructType cppType =
			new CppStructType(baseCategoryPath, symbolPath, composite, mangledName);
		cppType.setName(name);
		cppType.setSize(size);
		return cppType;
	}

	private static class CppClassType extends CppCompositeType {
		private CppClassType(CategoryPath baseCategoryPath, SymbolPath symbolPath,
				Composite composite, String mangledName) {
			super(baseCategoryPath, symbolPath, composite, mangledName);
			setClass();
		}
	}

	private static class CppStructType extends CppCompositeType {
		private CppStructType(CategoryPath baseCategoryPath, SymbolPath symbolPath,
				Composite composite, String mangledName) {
			super(composite.getCategoryPath(), symbolPath, composite, mangledName);
			setStruct();
		}
	}

	static boolean validateMangledCompositeName(String mangledCompositeTypeName, ClassKey type) {
		if (mangledCompositeTypeName == null) {
			return false;
		}
		if (!mangledCompositeTypeName.startsWith(".?")) {
			return false;
		}
		if (mangledCompositeTypeName.length() < 7) {
			return false;
		}
		if (mangledCompositeTypeName.charAt(2) != 'A') {
			PdbLog.message("Mangled composite type name not plain 'A'");
		}
		switch (mangledCompositeTypeName.charAt(3)) {
			case 'T':
				if ((type.compareTo(ClassKey.UNION) != 0) &&
					(type.compareTo(ClassKey.UNKNOWN) != 0)) {
					PdbLog.message("Warning: Mismatched complex type 'T' for " + type);
				}
				break;
			case 'U':
				if ((type.compareTo(ClassKey.STRUCT) != 0) &&
					(type.compareTo(ClassKey.UNKNOWN) != 0)) {
					PdbLog.message("Warning: Mismatched complex type 'U' for " + type);
				}
				break;
			case 'V':
				if ((type.compareTo(ClassKey.CLASS) != 0) &&
					(type.compareTo(ClassKey.UNKNOWN) != 0)) {
					PdbLog.message("Warning: Mismatched complex type 'V' for " + type);
				}
				break;
			default:
				PdbLog.message("Not composite");
				return false;
		}
		return true;

	}

	public boolean validate() {
		// C++ rules:
		// If final, can have an empty name.  I believe this means "name" can be empty, but
		//  can still have parent namespace.  TODO: check this if we change to something more
		//  than String.
		if (StringUtils.isEmpty(className) && !isFinal) {
			return false;
		}
		return true;
	}

	private List<LayoutBaseClass> getLayoutBaseClasses() {
		return layoutBaseClasses;
	}

	SymbolPath getSymbolPath() {
		return symbolPath;
	}

	Composite getComposite() {
		return composite;
	}

	public CategoryPath getCategoryPath() {
		return categoryPath;
	}

	public void setFinal(boolean isFinal) {
		this.isFinal = isFinal;
	}

	public boolean isFinal() {
		return isFinal;
	}

	public void setClass() {
		classKey = ClassKey.CLASS;
	}

	public void setStruct() {
		classKey = ClassKey.STRUCT;
	}

	public void setUnion() {
		classKey = ClassKey.UNION;
	}

	// not sure if user can see Type when returned.
	public ClassKey getType() {
		return classKey;
	}

	public void setName(String className) {
		this.className = className;
	}

	public String getName() {
		return className;
	}

	public DataTypePath getDataTypePath() {
		return composite.getDataTypePath();
	}

	public void setMangledName(String mangledName) {
		this.mangledName = mangledName;
	}

	public String getMangledName() {
		return mangledName;
	}

	public void setSize(int size) {
		this.size = size;
	}

	public int getSize() {
		return size;
	}

	public int getNumMembers() {
		return myMembers.size();
	}

	public int getNumLayoutMembers() {
		return layoutMembers.size();
	}

	public void addVirtualFunctionTablePointer(String name, DataType dataType, int offset) {
		Member newMember = new Member(name, dataType, false, ClassFieldAttributes.UNKNOWN, offset);
		layoutVftPtrMembers.add(newMember);
	}

	private void insertVirtualFunctionTablePointers(List<ClassPdbMember> pdbMembers) {
		for (Member vftPtrMember : layoutVftPtrMembers) {
			ClassPdbMember vftPtrPdbMember = new ClassPdbMember(vftPtrMember.getName(),
				vftPtrMember.getDataType(), vftPtrMember.isFlexibleArray(),
				vftPtrMember.getOffset(), vftPtrMember.getComment());
			int index = 0;
			for (ClassPdbMember member : pdbMembers) {
				if (member.getOffset() > vftPtrMember.getOffset()) {
					break;
				}
				index++;
			}
			pdbMembers.add(index, vftPtrPdbMember);
		}
	}

	public void addMember(String memberName, DataType dataType, boolean isFlexibleArray, int offset,
			String comment) {
		addMember(memberName, dataType, isFlexibleArray, ClassFieldAttributes.UNKNOWN, offset,
			comment);
	}

	public void addMember(String memberName, DataType dataType, boolean isFlexibleArray,
			int offset) {
		addMember(memberName, dataType, isFlexibleArray, ClassFieldAttributes.UNKNOWN, offset,
			null);
	}

	public void addMember(String memberName, DataType dataType, boolean isFlexibleArray,
			ClassFieldAttributes attributes, int offset) {
		Member newMember = new Member(memberName, dataType, isFlexibleArray, attributes, offset);
		myMembers.add(newMember);
		addMember(layoutMembers, newMember);
	}

	public void addMember(String memberName, DataType dataType, boolean isFlexibleArray,
			ClassFieldAttributes attributes, int offset, String comment) {
		Member newMember =
			new Member(memberName, dataType, isFlexibleArray, attributes, offset, comment);
		myMembers.add(newMember);
		addMember(layoutMembers, newMember);
	}

	private void addMember(List<Member> members, Member newMember) {
		members.add(newMember);
	}

	//==============================================================================================
	/*
	 * These "insert" methods should be used judiciously.  You need to know what/why you are doing
	 * this.  Changing the order of "normal" members can mess up the layout algorithms from
	 * {@link DefaultCompositeMember}.  The only place we currently think we can use these is
	 * when trying to place vbptr members.  Not all of these methods are used too.
	 * @param isFlexibleArray TODO
	 */
	public void insertMember(String memberName, DataType dataType, boolean isFlexibleArray,
			int offset, String comment) {
		insertMember(memberName, dataType, isFlexibleArray, ClassFieldAttributes.UNKNOWN, offset,
			comment);
	}

	public void insertMember(String memberName, DataType dataType, boolean isFlexibleArray,
			int offset) {
		insertMember(memberName, dataType, isFlexibleArray, ClassFieldAttributes.UNKNOWN, offset,
			null);
	}

	public void insertMember(String memberName, DataType dataType, boolean isFlexibleArray,
			ClassFieldAttributes attributes, int offset) {
		Member newMember = new Member(memberName, dataType, isFlexibleArray, attributes, offset);
		myMembers.add(newMember);
		insertMember(layoutMembers, newMember);
	}

	public void insertMember(String memberName, DataType dataType, boolean isFlexibleArray,
			ClassFieldAttributes attributes, int offset, String comment) {
		Member newMember =
			new Member(memberName, dataType, isFlexibleArray, attributes, offset, comment);
		myMembers.add(newMember);
		insertMember(layoutMembers, newMember);
	}

	private void insertMember(List<Member> members, Member newMember) {
		int index = 0;
		for (Member member : members) {
			if (member.getOffset() > newMember.getOffset()) {
				break;
			}
			index++;
		}
		members.add(index, newMember);
	}

	public void addStaticMember(String memberName, DataType dataType) {
		addStaticMember(memberName, dataType, ClassFieldAttributes.UNKNOWN);
	}

	public void addStaticMember(String memberName, DataType dataType,
			ClassFieldAttributes attributes) {
		myMembers.add(new StaticMember(memberName, dataType, attributes));
	}

	public int getNumLayoutBaseClasses() {
		return layoutBaseClasses.size();
	}

	public int getNumLayoutVirtualBaseClasses() {
		int num = 0;
		for (LayoutBaseClass base : layoutBaseClasses) {
			if (base instanceof DirectLayoutBaseClass) {
				num++;
			}
		}
		return layoutBaseClasses.size() - num;
	}

	public int getNumSyntacticBaseClasses() {
		return syntacticBaseClasses.size();
	}

	public void addSyntacticBaseClass(CppCompositeType baseClassType) throws PdbException {
		addSyntacticBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN);
	}

	public void addSyntacticBaseClass(CppCompositeType baseClassType,
			ClassFieldAttributes attributes) throws PdbException {
		validateBaseClass(baseClassType);
		syntacticBaseClasses.add(new SyntacticBaseClass(baseClassType, attributes));
	}

	public void addDirectSyntacticBaseClass(CppCompositeType baseClassType) throws PdbException {
		addDirectSyntacticBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN);
	}

	public void addDirectSyntacticBaseClass(CppCompositeType baseClassType,
			ClassFieldAttributes attributes) throws PdbException {
		validateBaseClass(baseClassType);
		syntacticBaseClasses.add(new DirectSyntacticBaseClass(baseClassType, attributes));
	}

	public void addVirtualSyntacticBaseClass(CppCompositeType baseClassType) throws PdbException {
		addVirtualSyntacticBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN);
	}

	public void addVirtualSyntacticBaseClass(CppCompositeType baseClassType,
			ClassFieldAttributes attributes) throws PdbException {
		validateBaseClass(baseClassType);
		syntacticBaseClasses.add(new VirtualSyntacticBaseClass(baseClassType, attributes));
	}

	public void insertSyntacticBaseClass(CppCompositeType baseClassType, int ordinal)
			throws PdbException {
		insertSyntacticBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN, ordinal);
	}

	public void insertSyntacticBaseClass(CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int ordinal) throws PdbException {
		validateBaseClass(baseClassType);
		if (ordinal < 0 || ordinal > getNumSyntacticBaseClasses()) {
			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
			throw new PdbException("Invalid base class insertion index.");
		}
		syntacticBaseClasses.add(ordinal, new SyntacticBaseClass(baseClassType, attributes));
	}

	public void insertDirectSyntacticBaseClass(CppCompositeType baseClassType, int ordinal)
			throws PdbException {
		insertDirectSyntacticBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN, ordinal);
	}

	public void insertDirectSyntacticBaseClass(CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int ordinal) throws PdbException {
		validateBaseClass(baseClassType);
		if (ordinal < 0 || ordinal > getNumSyntacticBaseClasses()) {
			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
			throw new PdbException("Invalid base class insertion index.");
		}
		syntacticBaseClasses.add(ordinal, new DirectSyntacticBaseClass(baseClassType, attributes));
	}

	public void insertVirtualSyntacticBaseClass(CppCompositeType baseClassType, int ordinal)
			throws PdbException {
		insertVirtualSyntacticBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN, ordinal);
	}

	public void insertVirtualSyntacticBaseClass(CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int ordinal) throws PdbException {
		validateBaseClass(baseClassType);
		if (ordinal < 0 || ordinal > getNumSyntacticBaseClasses()) {
			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
			throw new PdbException("Invalid base class insertion index.");
		}
		syntacticBaseClasses.add(ordinal, new VirtualSyntacticBaseClass(baseClassType, attributes));
	}

	//==============================================================================================
	public void addDirectBaseClass(CppCompositeType baseClassType, int offset) throws PdbException {
		addDirectBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN, offset);
	}

	public void addDirectBaseClass(CppCompositeType baseClassType, ClassFieldAttributes attributes,
			int offset) throws PdbException {
		validateBaseClass(baseClassType);
		layoutBaseClasses.add(new DirectLayoutBaseClass(baseClassType, attributes, offset));
	}

//	// Index is order in list, not physical offset of class elements.
//	public void insertDirectBaseClass(CppCompositeType baseClassType, int index)
//			throws PdbException {
//		insertDirectBaseClass(baseClassType,
//			new ClassFieldAttributes(Access.UNKNOWN, Property.UNKNOWN), index);
//	}
//
//	// Index is order in list, not physical offset of class elements.
//	public void insertDirectBaseClass(CppCompositeType baseClassType,
//			ClassFieldAttributes attributes, int index) throws PdbException {
//		validateBaseClass(baseClassType);
//		if (index < 0 || index > getNumBaseClasses()) {
//			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
//			throw new PdbException("Invalid base class insertion index.");
//		}
//		layoutBaseClasses.add(index, new DirectBaseClass(baseClassType, attributes));
//	}
//
	public void addDirectVirtualBaseClass(CppCompositeType baseClassType, int basePointerOffset,
			DataType vbptr, int offsetFromVbt) throws PdbException {
		addDirectVirtualBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN, basePointerOffset,
			vbptr, offsetFromVbt);
	}

	public void addDirectVirtualBaseClass(CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int basePointerOffset, DataType vbptr,
			int offsetFromVbt) throws PdbException {
		validateBaseClass(baseClassType);
		layoutBaseClasses.add(new DirectVirtualLayoutBaseClass(baseClassType, attributes,
			basePointerOffset, vbptr, offsetFromVbt));
	}

//	// Index is order in list, not physical offset of class elements.
//	public void insertDirectVirtualBaseClass(CppCompositeType baseClassType, int index)
//			throws PdbException {
//		insertDirectVirtualBaseClass(baseClassType,
//			new ClassFieldAttributes(Access.UNKNOWN, Property.UNKNOWN), index);
//	}
//
//	// Index is order in list, not physical offset of class elements.
//	public void insertDirectVirtualBaseClass(CppCompositeType baseClassType,
//			ClassFieldAttributes attributes, int index) throws PdbException {
//		validateBaseClass(baseClassType);
//		if (index < 0 || index > getNumBaseClasses()) {
//			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
//			throw new PdbException("Invalid base class insertion index.");
//		}
//		layoutBaseClasses.add(index, new DirectVirtualBaseClass(baseClassType, attributes));
//	}
//
	public void addIndirectVirtualBaseClass(CppCompositeType baseClassType, int basePointerOffset,
			DataType vbptr, int offsetFromVbt) throws PdbException {
		addIndirectVirtualBaseClass(baseClassType, ClassFieldAttributes.UNKNOWN, basePointerOffset,
			vbptr, offsetFromVbt);
	}

	public void addIndirectVirtualBaseClass(CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int basePointerOffset, DataType vbptr,
			int offsetFromVbt) throws PdbException {
		validateBaseClass(baseClassType);
		layoutBaseClasses.add(new IndirectVirtualLayoutBaseClass(baseClassType, attributes,
			basePointerOffset, vbptr, offsetFromVbt));
	}

//	// Index is order in list, not physical offset of class elements.
//	public void insertIndirectVirtualBaseClass(CppCompositeType baseClassType, int index)
//			throws PdbException {
//		insertIndirectVirtualBaseClass(baseClassType,
//			new ClassFieldAttributes(Access.UNKNOWN, Property.UNKNOWN), index);
//	}
//
//	// Index is order in list, not physical offset of class elements.
//	public void insertIndirectVirtualBaseClass(CppCompositeType baseClassType,
//			ClassFieldAttributes attributes, int index) throws PdbException {
//		validateBaseClass(baseClassType);
//		if (index < 0 || index > getNumBaseClasses()) {
//			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
//			throw new PdbException("Invalid base class insertion index.");
//		}
//		layoutBaseClasses.add(index, new IndirectVirtualBaseClass(baseClassType, attributes));
//	}
//
	private static void validateBaseClass(CppCompositeType baseClassType) throws PdbException {
		if (baseClassType.isFinal) {
			throw new PdbException("Cannot inherit base class marked final.");
		}
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append(classKey);
		builder.append(className);
		if (isFinal) {
			builder.append(" final");
		}
		StringBuilder baseBuilder = new StringBuilder();
		for (BaseClass base : syntacticBaseClasses) {
			if (baseBuilder.length() == 0) {
				baseBuilder.append(" : ");
			}
			else {
				baseBuilder.append(", ");
			}
			baseBuilder.append(base);
		}
		builder.append(baseBuilder);
		return builder.toString();
	}

	public ObjectOrientedClassLayout getLayout(ObjectOrientedClassLayout layoutOptions) {
		if (classLayout == null) {
			classLayout = determineClassLayout(layoutOptions);
		}
		return classLayout;
	}

	private ObjectOrientedClassLayout determineClassLayout(
			ObjectOrientedClassLayout layoutOptions) {
		ObjectOrientedClassLayout initialLayoutDetermination;
		if (layoutOptions == ObjectOrientedClassLayout.MEMBERS_ONLY) {
			return ObjectOrientedClassLayout.MEMBERS_ONLY;
		}
		else if (getNumLayoutBaseClasses() == 0) {
			initialLayoutDetermination = ObjectOrientedClassLayout.BASIC_SIMPLE_COMPLEX;
		}
		else if (getNumLayoutVirtualBaseClasses() == 0) {
			initialLayoutDetermination = ObjectOrientedClassLayout.SIMPLE_COMPLEX;
		}
		else {
			initialLayoutDetermination = ObjectOrientedClassLayout.COMPLEX;
		}
		ObjectOrientedClassLayout classLayoutOption = layoutOptions;
		return classLayoutOption.compareTo(initialLayoutDetermination) >= 0 ? classLayoutOption
				: initialLayoutDetermination;
	}

	boolean isZeroSize() {
		return memberData.size() == 0;
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	public void createLayoutFromSyntacticDescription(VxtManager vxtManager, TaskMonitor monitor) {
		for (SyntacticBaseClass base : syntacticBaseClasses) {
			if (base instanceof DirectSyntacticBaseClass) {

			}
			else { // VirtualSyntacticBaseClass

			}
		}
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	public void createLayout(ObjectOrientedClassLayout layoutOptions, VxtManager vxtManager,
			TaskMonitor monitor) throws PdbException, CancelledException {
		if (vxtManager instanceof MsftVxtManager) { // Information from PDB/program symbols
			// TODO: both same for now
			//doSpeculativeLayout(vxtManager, monitor);
			createVbtBasedLayout(layoutOptions, vxtManager, monitor);
		}
		else {
			createSpeculativeLayout(layoutOptions, vxtManager, monitor);
		}
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	public void createVbtBasedLayout(ObjectOrientedClassLayout layoutOptions, VxtManager vxtManager,
			TaskMonitor monitor) throws PdbException, CancelledException {
		CategoryPath cn;
		hasDirect = false;
		switch (getLayout(layoutOptions)) {
			case MEMBERS_ONLY:
				addLayoutPdbMembers(memberData, layoutMembers);
				break;
			case BASIC_SIMPLE_COMPLEX:
				addLayoutPdbMembers(memberData, layoutMembers);
				insertVirtualFunctionTablePointers(memberData);
				break;
			// TODO: evaluate... not really getting difference I thought we could get... so far
			//  BASIC and SIMPLE seem to yield the same results.  I might be doing something wrong.
			case SIMPLE_COMPLEX:
			case COMPLEX:
				cn = createDirectCategoryPath(this);
				Composite directDataType = new StructureDataType(cn.getParent(), cn.getName(), 0,
					composite.getDataTypeManager());

				List<ClassPdbMember> directClassPdbMembers = getDirectBaseClassMembers(monitor);
				List<VirtualLayoutBaseClass> myVirtualLayoutBases = preprocessVirtualBases(monitor);

				// TODO: consider moving down below next line.
				boolean allVbtFound =
					reconcileVirtualBaseTables(composite.getDataTypeManager(), vxtManager);

				addLayoutPdbMembers(directClassPdbMembers, layoutMembers);
				insertVirtualFunctionTablePointers(directClassPdbMembers);

				if (!DefaultCompositeMember.applyDataTypeMembers(directDataType, false, 0,
					directClassPdbMembers, msg -> Msg.warn(this, msg), monitor)) {
					clearComponents(directDataType);
				}
				int directClassLength = getCompositeLength(directDataType);

				if (directClassLength == 0) {
					// Not using the direct type (only used it to get the directClassLength), so
					//  remove it and add the members to the main type instead.
					directDataType.getDataTypeManager().remove(directDataType, monitor);
				}
				else {
					// this does not deal with the case where more members from memberData get
					// added below and must still fit in "size."
					if (directClassLength > size) {
						// Redo it with the size of the overall structure/class
						directDataType.getDataTypeManager().remove(directDataType, monitor);
						directDataType = new StructureDataType(cn.getParent(), cn.getName(), 0,
							composite.getDataTypeManager());
						if (!DefaultCompositeMember.applyDataTypeMembers(directDataType, false,
							size, directClassPdbMembers, msg -> Msg.warn(this, msg), monitor)) {
							clearComponents(directDataType);
						}
						directClassLength = getCompositeLength(directDataType);
					}
					if (getLayout(layoutOptions) == ObjectOrientedClassLayout.SIMPLE_COMPLEX) {
						// Not using the dummy/direct type (only used it to get the
						//  directClassLength), so remove it and add the members to the main
						//  type instead.
						directDataType.getDataTypeManager().remove(directDataType, monitor);
						memberData.addAll(directClassPdbMembers);
						//addLayoutPdbMembers(memberData, layoutMembers, monitor);
					}
					else {
						ClassPdbMember directClassPdbMember =
							new ClassPdbMember("", directDataType, false, 0, null);
						memberData.add(directClassPdbMember);
						hasDirect = true;
					}
				}

				addVirtualBases(directClassLength, memberData, myVirtualLayoutBases, allVbtFound,
					monitor);

				break;
			default:
				throw new PdbException("Unhandled layout mode");
		}

		if (!DefaultCompositeMember.applyDataTypeMembers(composite, false, size, memberData,
			msg -> Msg.warn(this, msg), monitor)) {
			clearComponents(composite);
		}
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	private List<ClassPdbMember> getDirectBaseClassMembers(TaskMonitor monitor)
			throws CancelledException {
		List<ClassPdbMember> myDirectClassPdbMembers = new ArrayList<>();
		TreeMap<Integer, Member> orderedBaseMembers = new TreeMap<>();
		for (LayoutBaseClass base : getLayoutBaseClasses()) {
			monitor.checkCancelled();
			CppCompositeType baseComposite = base.getBaseClassType();
			if (base instanceof DirectLayoutBaseClass) {
				if (!baseComposite.isZeroSize()) {
					Composite baseDataType = base.getDirectDataType();
					int offset = ((DirectLayoutBaseClass) base).getOffset();
					CategoryPath cn =
						getBaseCategoryName("BaseClass_" + base.getBaseClassType().getName());
					Member baseMember =
						new Member("", baseDataType, false, null, offset, cn.toString());
					orderedBaseMembers.put(offset, baseMember);
				}
			}
		}
		for (Member baseMember : orderedBaseMembers.values()) {
			addPdbMember(myDirectClassPdbMembers, baseMember);
		}
		return myDirectClassPdbMembers;
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	private List<VirtualLayoutBaseClass> preprocessVirtualBases(TaskMonitor monitor)
			throws CancelledException, PdbException {
		List<VirtualLayoutBaseClass> myVirtualLayoutBases = new ArrayList<>();
		for (LayoutBaseClass base : getLayoutBaseClasses()) {
			monitor.checkCancelled();
			if (base instanceof VirtualLayoutBaseClass) {
				addPlaceholderVirtualBaseTableEntry(((VirtualLayoutBaseClass) base));
				myVirtualLayoutBases.add((VirtualLayoutBaseClass) base);
			}
		}
		return myVirtualLayoutBases;
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	public void createSpeculativeLayout(ObjectOrientedClassLayout layoutOptions,
			VxtManager vxtManager, TaskMonitor monitor) throws PdbException, CancelledException {
		// Speculative Layout uses recursion to try to know the order of members.  However, MSFT
		//  rearranges the order of the Base Class records such that they are not necessarily in
		//  the order that the class was declared, and it seems that the member order follows the
		//  order of the class hierarchy declaration.
		// We use recursion and also also reordering so Base Classes always follow their children,
		//  so with multiple virtual inheritance, a parent from multiple family lines will likely
		//  get moved.
		CategoryPath cn;
		hasDirect = false;
		switch (getLayout(layoutOptions)) {
			case MEMBERS_ONLY:
				addLayoutPdbMembers(memberData, layoutMembers);
				break;
			case BASIC_SIMPLE_COMPLEX:
				cn = composite.getCategoryPath();
				addLayoutPdbMembers(memberData, layoutMembers);
				insertVirtualFunctionTablePointers(memberData);
				break;
			// TODO: evaluate... not really getting difference I thought we could get... so far
			//  BASIC and SIMPLE seem to yield the same results.  I might be doing something wrong.
			case SIMPLE_COMPLEX:
			case COMPLEX:
				cn = createDirectCategoryPath(this);
				Composite directDataType = new StructureDataType(cn.getParent(), cn.getName(), 0,
					composite.getDataTypeManager());

				List<LayoutBaseClass> myAccumulatedDirectBases = new ArrayList<>();
				List<VirtualLayoutBaseClass> myAccumulatedVirtualBases = new ArrayList<>();
				List<ClassPdbMember> directClassPdbMembers = new ArrayList<>();
				processBaseClassesRecursive(this, true, directClassPdbMembers,
					myAccumulatedDirectBases, myAccumulatedVirtualBases, 0, monitor);

				// TODO: consider moving down below next line.
				boolean allVbtFound =
					reconcileVirtualBaseTables(composite.getDataTypeManager(), vxtManager);

				addLayoutPdbMembers(directClassPdbMembers, layoutMembers);
				insertVirtualFunctionTablePointers(directClassPdbMembers);

				if (!DefaultCompositeMember.applyDataTypeMembers(directDataType, false, 0,
					directClassPdbMembers, msg -> Msg.warn(this, msg), monitor)) {
					clearComponents(directDataType);
				}
				int directClassLength = getCompositeLength(directDataType);

				if (directClassLength == 0) {
					// Not using the direct type (only used it to get the directClassLength), so
					//  remove it and add the members to the main type instead.
					directDataType.getDataTypeManager().remove(directDataType, monitor);
				}
				else {
					// this does not deal with the case where more members from memberData get
					// added below and must still fit in "size."
					if (directClassLength > size) {
						// Redo it with the size of the overall structure/class
						directDataType.getDataTypeManager().remove(directDataType, monitor);
						directDataType = new StructureDataType(cn.getParent(), cn.getName(), 0,
							composite.getDataTypeManager());
						if (!DefaultCompositeMember.applyDataTypeMembers(directDataType, false,
							size, directClassPdbMembers, msg -> Msg.warn(this, msg), monitor)) {
							clearComponents(directDataType);
						}
						directClassLength = getCompositeLength(directDataType);
					}
					if (getLayout(layoutOptions) == ObjectOrientedClassLayout.SIMPLE_COMPLEX) {
						// Not using the dummy/direct type (only used it to get the
						//  directClassLength), so remove it and add the members to the main
						//  type instead.
						directDataType.getDataTypeManager().remove(directDataType, monitor);
						memberData.addAll(directClassPdbMembers);
						//addLayoutPdbMembers(memberData, layoutMembers, monitor);
					}
					else {
						ClassPdbMember directClassPdbMember =
							new ClassPdbMember("", directDataType, false, 0, null);
						memberData.add(directClassPdbMember);
						hasDirect = true;
					}
				}

				addVirtualBasesSpeculatively(directClassLength, memberData,
					myAccumulatedVirtualBases, monitor);

				break;
			default:
				throw new PdbException("Unhandled layout mode");
		}

		if (!DefaultCompositeMember.applyDataTypeMembers(composite, false, size, memberData,
			msg -> Msg.warn(this, msg), monitor)) {
			clearComponents(composite);
		}
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	private void processBaseClassesRecursive(CppCompositeType cppType, boolean isDirect,
			List<ClassPdbMember> myPdbMembers, List<LayoutBaseClass> myAccumulatedDirectBases,
			List<VirtualLayoutBaseClass> myAccumulatedVirtualBases, int depth, TaskMonitor monitor)
			throws PdbException, CancelledException {
		depth++;
		for (LayoutBaseClass base : cppType.getLayoutBaseClasses()) {
			monitor.checkCancelled();
			CppCompositeType baseComposite = base.getBaseClassType();
			if (base instanceof DirectLayoutBaseClass) {
				if (isDirect) {
					if (alreadyAccumulatedByName(myAccumulatedDirectBases, base)) {
						throw new PdbException(
							"Direct base already seen: " + base.getBaseClassType().getName());
					}
					if (!baseComposite.isZeroSize()) {
						Composite baseDataType = base.getDirectDataType();
						int offset = ((DirectLayoutBaseClass) base).getOffset();
						CategoryPath cn =
							getBaseCategoryName("BaseClass_" + base.getBaseClassType().getName());
						Member baseMember =
							new Member("", baseDataType, false, null, offset, cn.toString());
						addPdbMember(myPdbMembers, baseMember);
					}
					myAccumulatedDirectBases.add(base);
				}
				processBaseClassesRecursive(baseComposite, false, myPdbMembers,
					myAccumulatedDirectBases, myAccumulatedVirtualBases, depth, monitor);
			}
			else if (base instanceof VirtualLayoutBaseClass) {
				if (depth == 1) {
					addPlaceholderVirtualBaseTableEntry(((VirtualLayoutBaseClass) base));
				}
				if (alreadyAccumulatedByName(myAccumulatedVirtualBases, base)) {
					continue;
				}
				if (!baseComposite.isZeroSize()) {
					processBaseClassesRecursive(baseComposite, false, myPdbMembers,
						myAccumulatedDirectBases, myAccumulatedVirtualBases, depth, monitor);
				}
				myAccumulatedVirtualBases.add((VirtualLayoutBaseClass) base);
			}
			else {
				throw new PdbException("Unknown base class type");
			}
		}
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	void addPlaceholderVirtualBaseTableEntry(VirtualLayoutBaseClass base) throws PdbException {
		PlaceholderVirtualBaseTable table =
			placeholderVirtualBaseTables.get(base.getBasePointerOffset());
		if (table == null) {
			table = new PlaceholderVirtualBaseTable();
			placeholderVirtualBaseTables.put(base.getBasePointerOffset(), table);
		}
		PlaceholderVirtualBaseTableEntry entry =
			table.getEntryByIndexInTable(base.getOffetFromVbt());
		if (entry != null) {
			throw new PdbException(
				"Entry already exists at offset (" + base.getOffetFromVbt() + "): " + entry);
		}
		entry = new PlaceholderVirtualBaseTableEntry(base);
		table.addEntry(base.getOffetFromVbt(), entry);
	}

	PlaceholderVirtualBaseTable getPlaceholderVirtualBaseTable(int basePointerOffset) {
		return placeholderVirtualBaseTables.get(basePointerOffset);
	}

	Map<Integer, PlaceholderVirtualBaseTable> getPlaceholderVirtualBaseTables() {
		return placeholderVirtualBaseTables;
	}

	private boolean reconcileVirtualBaseTables(DataTypeManager dtm, VxtManager vxtManager)
			throws PdbException {
		if (placeholderVirtualBaseTables.size() > 1) {
			// study this.
		}

		boolean allVbtFound = true;
		for (Entry<Integer, PlaceholderVirtualBaseTable> tableEntry : placeholderVirtualBaseTables
				.entrySet()) {
			int vbtptrOffset = tableEntry.getKey();
			PlaceholderVirtualBaseTable table = tableEntry.getValue();
			if (!table.validateOffset()) {
				// TODO study this.
			}
			DataType vbptr = getVbptrDataType(dtm, vxtManager, table);
			allVbtFound &=
				addOrUpdateVbtAndVbtptrMember(vxtManager, table, vbptr, vbtptrOffset, getName());
		}
		return allVbtFound;
	}

	private DataType getVbptrDataType(DataTypeManager dtm, VxtManager vxtManager,
			PlaceholderVirtualBaseTable table) {
		DataType vbptr = null;
		for (int index = 1; index < table.getMaxOffset(); index++) {
			PlaceholderVirtualBaseTableEntry entry = table.getEntryByIndexInTable(index);
			vbptr = entry.getVirtualBaseClass().getVbptr();
			if (vbptr != null) { // take first type... assuming all are the same
				break;
			}
		}
		if (vbptr == null) {
			vbptr = vxtManager.getDefaultVbtPtr();
		}
		return vbptr;
	}

	private record CppParentageAndMember(List<CppCompositeType> parentage, Member member) {}

	private boolean addOrUpdateVbtAndVbtptrMember(VxtManager vxtManager,
			PlaceholderVirtualBaseTable table, DataType vbptr, int vbtptrOffset, String myClass)
			throws PdbException {

		// TODO: if we want to match vbtables with the pointers in *virtual* base classes, we are
		//  not currently doing the work... we are only looking for direct bases, as they are
		//  what dictate the placement for our current class (though cross-checks could be done
		//  with all vbtables (at some point))

		List<CppCompositeType> parentage = new ArrayList<>();

		CppParentageAndMember cAndP = findDirectBaseParentageAndMember(this, 0, vbtptrOffset);

		if (cAndP == null) {
			insertMember("{vbptr}", vbptr, false, vbtptrOffset, "{vbptr} for " + myClass);
		}
		else if (!"{vbptr}".equals(cAndP.member().getName())) {
			String message = "PDB: Collision of non-{vbptr}.";
			PdbLog.message(message);
			Msg.info(this, message);
			return false;
		}
		else {
			parentage = cAndP.parentage();
		}
		if (!(vxtManager instanceof MsftVxtManager mvxtManager)) {
			return false;
		}
		int entrySize = 4; // Default to something (could be wrong)
		if (vbptr instanceof PointerDataType) {
			entrySize = ((PointerDataType) vbptr).getDataType().getLength();
		}
		boolean x = findVbt(table, mvxtManager, entrySize, symbolPath, parentage);
		return x;
	}

	private boolean findVbt(PlaceholderVirtualBaseTable table, MsftVxtManager mvbtm, int entrySize,
			SymbolPath ownerSp, List<CppCompositeType> parentage) {

		ClassID mId = new ProgramClassID(baseCategoryPath, ownerSp);
		List<ClassID> cIdParentage = new ArrayList<>();
		for (CppCompositeType t : parentage) {
			ClassID id = new ProgramClassID(t.baseCategoryPath, t.getSymbolPath());
			cIdParentage.add(id);
		}
		ProgramVirtualBaseTable vbt = (ProgramVirtualBaseTable) mvbtm.findPrimaryVbt(mId);
		//ProgramVirtualBaseTable vbt = (ProgramVirtualBaseTable) mvbtm.findVbt(mId, cIdParentage);

		table.setVirtualBaseTable(vbt);

		return vbt != null;
	}

	private CppParentageAndMember findDirectBaseParentageAndMember(CppCompositeType cppType,
			int offsetCppType, int vbtptrOffset) throws PdbException {
		for (LayoutBaseClass base : cppType.layoutBaseClasses) {
			if (!(base instanceof DirectLayoutBaseClass)) {
				continue;
			}
			DirectLayoutBaseClass directBase = (DirectLayoutBaseClass) base;
			int directBaseOffset = directBase.getOffset() + offsetCppType;
			int directBaseLength = directBase.getDirectDataType().getLength();
			if (vbtptrOffset >= directBaseOffset &&
				vbtptrOffset < directBaseOffset + directBaseLength) {
				CppCompositeType childCppType = directBase.getBaseClassType();
				CppParentageAndMember cAndP =
					findDirectBaseParentageAndMember(childCppType, directBaseOffset, vbtptrOffset);
				if (cAndP == null) {
					Member member = childCppType.findLayoutMemberOrVftPtrMember(vbtptrOffset);
					if (member == null) {
						return null;
					}
					cAndP = new CppParentageAndMember(new ArrayList<>(), member);
				}
				List<CppCompositeType> parentage = cAndP.parentage();
				parentage.add(childCppType);
				return cAndP;
			}
		}
		return null;
	}

	private Member findLayoutMemberOrVftPtrMember(int offset) {
		for (Member member : layoutMembers) {
			if (member.getOffset() == offset) {
				return member;
			}
		}
		for (Member member : layoutVftPtrMembers) {
			if (member.getOffset() == offset) {
				return member;
			}
		}
		return null;
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
//	private void addVirtualBases(int startOffset, List<ClassPdbMember> pdbMembers,
//			List<VirtualLayoutBaseClass> virtualBases, boolean allVbtFound, TaskMonitor monitor)
//			throws PdbException, CancelledException {
//		String accumulatedComment = "";
//		int memberOffset = startOffset;
//		for (VirtualLayoutBaseClass virtualBase : virtualBases) {
//			monitor.checkCancelled();
//			Composite baseDataType = virtualBase.getDirectDataType();
//			int virtualBaseLength = getCompositeLength(baseDataType);
//			PlaceholderVirtualBaseTable pvbt =
//				getPlaceholderVirtualBaseTable(virtualBase.getBasePointerOffset());
//			if (pvbt != null && pvbt.canLookupOffset()) {
//				long offset = pvbt.getOffset(virtualBase.getOffetFromVbt());
//				memberOffset = (int) (offset & 0xffffffffL);
//			}
//			if (virtualBaseLength != 0) {
//				String comment =
//					"(Virtual Base " + virtualBase.getDataTypePath().getDataTypeName() + ")";
//				accumulatedComment += comment;
//				ClassPdbMember virtualClassPdbMember =
//					new ClassPdbMember("", baseDataType, false, memberOffset, accumulatedComment);
//				pdbMembers.add(virtualClassPdbMember);
//				memberOffset += virtualBaseLength;
//				accumulatedComment = "";
//			}
//			else {
//				String comment = "((empty) Virtual Base " +
//					virtualBase.getDataTypePath().getDataTypeName() + ")";
//				accumulatedComment += comment;
//			}
//			// If last base is empty, then its comment and any accumulated to this point
//			//  will not be seen (not applied to a PdbMember).  TODO: Consider options,
//			//  though we know we have left it in this state and are OK with it for now.
//			//  We have not considered fall-out from this.
//		}
//	}

	private void addVirtualBases(int startOffset, List<ClassPdbMember> pdbMembers,
			List<VirtualLayoutBaseClass> virtualBases, boolean allVbtFound, TaskMonitor monitor)
			throws PdbException, CancelledException {
		String accumulatedComment = "";
		int memberOffset = startOffset;
		List<VirtualLayoutBaseClass> orderedBases = new ArrayList<>();
		List<Integer> offsets = new ArrayList<>();
		if (!orderVirtualBases(orderedBases, offsets, virtualBases, monitor)) {
			addVirtualBasesSpeculatively(startOffset, pdbMembers, virtualBases, monitor);
			return;
		}

		for (int index = 0; index < offsets.size(); index++) {
			monitor.checkCancelled();
			VirtualLayoutBaseClass virtualBase = orderedBases.get(index);
			memberOffset = offsets.get(index);
			Composite baseDataType = virtualBase.getDirectDataType();
			int virtualBaseLength = getCompositeLength(baseDataType);
			int basePointerOffset = virtualBase.getBasePointerOffset();
//			PlaceholderVirtualBaseTable pvbt =
//				getPlaceholderVirtualBaseTable(virtualBase.getBasePointerOffset());
//			if (pvbt != null && pvbt.canLookupOffset()) {
//				long offset = pvbt.getOffset(virtualBase.getOffetFromVbt());
//				memberOffset = (int) (offset & 0xffffffffL);
//			}
			memberOffset += basePointerOffset;
			if (virtualBaseLength != 0) {
				String comment =
					"(Virtual Base " + virtualBase.getDataTypePath().getDataTypeName() + ")";
				accumulatedComment += comment;
				ClassPdbMember virtualClassPdbMember =
					new ClassPdbMember("", baseDataType, false, memberOffset, accumulatedComment);
				pdbMembers.add(virtualClassPdbMember);
				memberOffset += virtualBaseLength;
				accumulatedComment = "";
			}
			else {
				String comment = "(Virtual Base (empty) " +
					virtualBase.getDataTypePath().getDataTypeName() + ")";
				accumulatedComment += comment;
			}
			// If last base is empty, then its comment and any accumulated to this point
			//  will not be seen (not applied to a PdbMember).  TODO: Consider options,
			//  though we know we have left it in this state and are OK with it for now.
			//  We have not considered fall-out from this.
		}
	}

	private boolean orderVirtualBases(List<VirtualLayoutBaseClass> ordered, List<Integer> offsets,
			List<VirtualLayoutBaseClass> unordered, TaskMonitor monitor)
			throws PdbException, CancelledException {
		for (VirtualLayoutBaseClass insertBase : unordered) {
			monitor.checkCancelled();
			PlaceholderVirtualBaseTable pvbt =
				getPlaceholderVirtualBaseTable(insertBase.getBasePointerOffset());
			if (pvbt == null || !pvbt.canLookupOffset()) {
				return false;
			}
			long offset = pvbt.getOffset(insertBase.getOffetFromVbt());
			int memberOffset = (int) (offset & 0xffffffffL);
			int index;
			for (index = 0; index < offsets.size(); index++) {
				int existingOffset = offsets.get(index);
				if (existingOffset > memberOffset) {
					break;
				}
			}
			ordered.add(index, insertBase);
			offsets.add(index, memberOffset);
		}
		return true;
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	private void addVirtualBasesSpeculatively(int startOffset, List<ClassPdbMember> pdbMembers,
			List<VirtualLayoutBaseClass> virtualBases, TaskMonitor monitor)
			throws CancelledException {
		String accumulatedComment = "";
		int memberOffset = startOffset;
		for (VirtualLayoutBaseClass virtualBase : virtualBases) {
			monitor.checkCancelled();
			Composite baseDataType = virtualBase.getDirectDataType();
			int virtualBaseLength = getCompositeLength(baseDataType);

			if (virtualBaseLength != 0) {
				String comment = "((Speculative Placement) Virtual Base " +
					virtualBase.getDataTypePath().getDataTypeName() + ")";
				accumulatedComment += comment;
				ClassPdbMember virtualClassPdbMember =
					new ClassPdbMember("", baseDataType, false, memberOffset, accumulatedComment);
				pdbMembers.add(virtualClassPdbMember);
				memberOffset += virtualBaseLength;
				accumulatedComment = "";
			}
			else {
				String comment = "((empty) (Speculative Placement) Virtual Base " +
					virtualBase.getDataTypePath().getDataTypeName() + ")";
				accumulatedComment += comment;
			}
			// If last base is empty, then its comment and any accumulated to this point
			//  will not be seen (not applied to a PdbMember).  TODO: Consider options,
			//  though we know we have left it in this state and are OK with it for now.
			//  We have not considered fall-out from this.
		}
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	private void addLayoutPdbMembers(List<ClassPdbMember> pdbMembers, List<Member> members) {
		for (Member member : members) {
			addPdbMember(pdbMembers, member);
		}
	}

	void addPdbMember(List<ClassPdbMember> pdbMembers, Member member) {
		ClassPdbMember classPdbMember = new ClassPdbMember(member.getName(), member.getDataType(),
			member.isFlexibleArray(), member.getOffset(), member.getComment());
		pdbMembers.add(classPdbMember);
	}

	void insertPdbMember(List<ClassPdbMember> pdbMembers, Member member) {
		ClassPdbMember classPdbMember = new ClassPdbMember(member.getName(), member.getDataType(),
			member.isFlexibleArray(), member.getOffset(), null);
		int index = 0;
		for (ClassPdbMember existingMember : pdbMembers) {
			if (existingMember.getOffset() > member.getOffset()) {
				break;
			}
			index++;
		}
		pdbMembers.add(index, classPdbMember);
	}

	private int getCompositeLength(Composite myComposite) {
		if (!myComposite.isZeroLength()) {
			return myComposite.getLength();
		}
		return 0;
	}

	private static boolean alreadyAccumulatedByName(List<? extends LayoutBaseClass> list,
			LayoutBaseClass item) {
		DataTypePath dtp = item.getDataTypePath();
		for (LayoutBaseClass iterated : list) {
			if (dtp.equals(iterated.getDataTypePath())) {
				return true;
			}
		}
		return false;
	}

	CategoryPath getBaseCategoryName(String baseName) {
		CategoryPath cn = getCategoryPath();
		return new CategoryPath(cn, baseName);
	}

	// TODO:
	// Taken from PdbUtil without change.  Would have had to change access on class PdbUtil and
	//  this ensureSize method to public to make it accessible.  Can revert to using PdbUtil
	//  once we move this new module from Contrib to Features/PDB.
	final static void clearComponents(Composite composite) {
		if (composite instanceof Structure) {
			((Structure) composite).deleteAll();
		}
		else {
			while (composite.getNumComponents() > 0) {
				composite.delete(0);
			}
		}
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	private abstract class BaseClass {
		// In the future, if CppClassType is a formal DataType, then we want to be able to get
		// an already-formed unique class from the DTM.  There is no reason to have a base
		// class duplicated as individually created components of DirectBaseClasses.
		private CppCompositeType baseClassType;
		private ClassFieldAttributes attributes;

		private BaseClass(CppCompositeType baseClassType, ClassFieldAttributes attributes) {
			this.baseClassType = baseClassType;
			this.attributes = attributes;
		}

		CppCompositeType getBaseClassType() {
			return baseClassType;
		}

		ClassFieldAttributes getAttributes() {
			return attributes;
		}

		ObjectOrientedClassLayout getLayoutMode(ObjectOrientedClassLayout layoutOptions) {
			return baseClassType.getLayout(layoutOptions);
		}

		DataTypePath getDataTypePath() {
			return new DataTypePath(baseClassType.getCategoryPath().getParent(),
				baseClassType.getCategoryPath().getName());
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(attributes);
			builder.append(baseClassType.getName());
			return builder.toString();
		}

		Composite getDirectDataType() {
			Composite c = getBaseClassType().getComposite();
			if (c.getNumComponents() == 0) {
				return c;
			}
			if (!baseClassType.hasDirect) {
				return c;
			}
			DataTypeComponent dtc = c.getComponent(0); // by construction this should be "Direct"
			DataType dt = dtc.getDataType();
			Structure bdt;
			if (!(dt instanceof Structure)) {
				throw new AssertException("Not Structure for Direct");
			}
			bdt = (Structure) dt;
			return bdt;
		}

	}

	//----------------------------------------------------------------------------------------------
	// Syntactic description of base classes.
	//----------------------------------------------------------------------------------------------
	private class SyntacticBaseClass extends BaseClass {
		private SyntacticBaseClass(CppCompositeType baseClassType,
				ClassFieldAttributes attributes) {
			super(baseClassType, attributes);
		}
	}

	private class DirectSyntacticBaseClass extends SyntacticBaseClass {
		private DirectSyntacticBaseClass(CppCompositeType baseClassType,
				ClassFieldAttributes attributes) {
			super(baseClassType, attributes);
		}
	}

	private class VirtualSyntacticBaseClass extends SyntacticBaseClass {
		private VirtualSyntacticBaseClass(CppCompositeType baseClassType,
				ClassFieldAttributes attributes) {
			super(baseClassType, attributes);
		}
	}

	//----------------------------------------------------------------------------------------------
	//  Layout description of base classes follow
	//----------------------------------------------------------------------------------------------
	private abstract class LayoutBaseClass extends BaseClass {
		Structure layout = null;

		LayoutBaseClass(CppCompositeType baseClassType, ClassFieldAttributes attributes) {
			super(baseClassType, attributes);
		}

		void setLayout(Structure layout) {
			this.layout = layout;
		}

		Structure getLayout() {
			if (layout == null) {
				// consider what to do here...
			}
			return layout;
		}
	}

	private class DirectLayoutBaseClass extends LayoutBaseClass {
		private int offset;

		private DirectLayoutBaseClass(CppCompositeType baseClassType,
				ClassFieldAttributes attributes, int offset) {
			super(baseClassType, attributes);
			this.offset = offset;
		}

		int getOffset() {
			return offset;
		}
	}

	private abstract class VirtualLayoutBaseClass extends LayoutBaseClass {
		private int basePointerOffset;
		private DataType vbptr;
		private int offsetFromVbt;

		private VirtualLayoutBaseClass(CppCompositeType baseClass, ClassFieldAttributes attributes,
				int basePointerOffset, DataType vbptr, int offsetFromVbt) {
			super(baseClass, attributes);
			this.basePointerOffset = basePointerOffset;
			this.vbptr = vbptr;
			this.offsetFromVbt = offsetFromVbt;
		}

		DataType getVbptr() {
			return vbptr;
		}

		int getOffetFromVbt() {
			return offsetFromVbt;
		}

		int getBasePointerOffset() {
			return basePointerOffset;
		}
	}

	private class DirectVirtualLayoutBaseClass extends VirtualLayoutBaseClass {
		private DirectVirtualLayoutBaseClass(CppCompositeType baseClass,
				ClassFieldAttributes attributes, int basePointerOffset, DataType vbptr,
				int offsetFromVbt) {
			super(baseClass, attributes, basePointerOffset, vbptr, offsetFromVbt);
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(super.toString());
			if (builder.length() > 0) {
				builder.append(">");
				builder.insert(0, "<");
			}
			return builder.toString();
		}
	}

	private class IndirectVirtualLayoutBaseClass extends VirtualLayoutBaseClass {
		private IndirectVirtualLayoutBaseClass(CppCompositeType baseClass,
				ClassFieldAttributes attributes, int basePointerOffset, DataType vbptr,
				int offsetFromVbt) {
			super(baseClass, attributes, basePointerOffset, vbptr, offsetFromVbt);
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(super.toString());
			if (builder.length() > 0) {
				builder.append(">");
				builder.insert(0, "<indirect ");
			}
			return builder.toString();
		}
	}

	//----------------------------------------------------------------------------------------------

	//TODO: look into enumerates
	//TODO: look into nested type
	//TODO: look into nested typedef

	private abstract class AbstractMember {
		private String memberName;
		private DataType dataType;
		private boolean isFlexibleArray;
		private ClassFieldAttributes attributes;
		private String comment;

		private AbstractMember(String name, DataType dataType, boolean isFlexibleArray,
				ClassFieldAttributes attributes) {
			this(name, dataType, isFlexibleArray, attributes, null);
		}

		private AbstractMember(String name, DataType dataType, boolean isFlexibleArray,
				ClassFieldAttributes attributes, String comment) {
			this.memberName = name;
			this.dataType = dataType;
			this.isFlexibleArray = isFlexibleArray;
			this.attributes = attributes;
			this.comment = comment;
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(dataType);
			if (builder.length() > 0 && memberName.length() > 0) {
				builder.append(' ');
			}
			builder.append(memberName);
			return builder.toString();
		}

		String getName() {
			return memberName;
		}

		DataType getDataType() {
			return dataType;
		}

		boolean isFlexibleArray() {
			return isFlexibleArray;
		}

		ClassFieldAttributes getAttributes() {
			return attributes;
		}

		void setComment(String comment) {
			this.comment = comment;
		}

		String getComment() {
			return comment;
		}
	}

	private class StaticMember extends AbstractMember {
		private StaticMember(String name, DataType dataType, ClassFieldAttributes attributes) {
			super(name, dataType, false, attributes);
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(super.toString());
			if (builder.length() > 0) {
				builder.insert(0, "static ");
			}
			return builder.toString();
		}
	}

	private class Member extends AbstractMember {
		private int offset;

		private Member(String name, DataType dataType, boolean isFlexibleArray,
				ClassFieldAttributes attributes, int offset) {
			this(name, dataType, isFlexibleArray, attributes, offset, null);
		}

		private Member(String name, DataType dataType, boolean isFlexibleArray,
				ClassFieldAttributes attributes, int offset, String comment) {
			super(name, dataType, isFlexibleArray, attributes, comment);
			this.offset = offset;
		}

		int getOffset() {
			return offset;
		}

	}

	//----------------------------------------------------------------------------------------------

	// Specific to PDB in name (Extends PdbMember... maybe should have more generic name)
	private static class ClassPdbMember extends PdbMember {

		private DataType dataType;
		private boolean isFlexibleArray;

		/**
		 * Class PDB member construction
		 * @param name member field name.
		 * @param dataType for the field.
		 * @param isFlexibleArray TODO
		 * @param offset member's byte offset within the root composite.
		 * @param comment comment for structure editor comment field; can be null.
		 */
		ClassPdbMember(String name, DataType dataType, boolean isFlexibleArray, int offset,
				String comment) {
			super(name, dataType.getName(), offset, comment);
			this.dataType = dataType;
			this.isFlexibleArray = isFlexibleArray;
		}

		@Override
		public String getDataTypeName() {
			return dataType.getName();
		}

		@Override
		protected WrappedDataType getDataType() throws CancelledException {
			return new WrappedDataType(dataType, isFlexibleArray, false);
		}
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	static class PlaceholderVirtualBaseTableEntry {
		VirtualLayoutBaseClass virtualBaseClass;
		int offsetInClass;

		PlaceholderVirtualBaseTableEntry(VirtualLayoutBaseClass virtualBaseClass) {
			this.virtualBaseClass = virtualBaseClass;
		}

		void setOffsetInClass(int offsetInClass) {
			this.offsetInClass = offsetInClass;
		}

		int getOffsetInClass() {
			return offsetInClass;
		}

		String getName() {
			return virtualBaseClass.getBaseClassType().getName();
		}

		VirtualLayoutBaseClass getVirtualBaseClass() {
			return virtualBaseClass;
		}
	}

	//----------------------------------------------------------------------------------------------
	static class PlaceholderVirtualBaseTable {
		private String name;
		private ProgramVirtualBaseTable vbt = null;

		// We do not know if every index will be given.  We can check after the fact, and once
		// the set of sequential integers is assured, we could create a list.
		private Map<Integer, PlaceholderVirtualBaseTableEntry> entriesByIndex;

		PlaceholderVirtualBaseTable() {
			this("");
		}

		PlaceholderVirtualBaseTable(String name) {
			this.name = name;
			entriesByIndex = new HashMap<>();
		}

		String getName() {
			return name;
		}

		void setName(String name) {
			this.name = name;
		}

		void setVirtualBaseTable(ProgramVirtualBaseTable vbt) {
			this.vbt = vbt;
		}

		boolean canLookupOffset() {
			return vbt != null;
		}

		long getOffset(int ordinal) throws PdbException {
			if (vbt != null) {
				return vbt.getBaseOffset(ordinal);
			}
			throw new PdbException("pdbVirtualBaseTable not initialized");
		}

		Map<Integer, PlaceholderVirtualBaseTableEntry> getEntries() {
			return entriesByIndex;
		}

		int getMaxOffset() {
			return entriesByIndex.size() + 1;
		}

		// TODO: maybe this should be called validateTableIndicies()
		boolean validateOffset() {
			int num = entriesByIndex.size() + 1; // assuming 0, plus 1-N)
			for (int index : entriesByIndex.keySet()) {
				if (index > num || index < 0) {
					return false;
				}
			}
			return true;
		}

		void addEntry(int indexInTable, PlaceholderVirtualBaseTableEntry entry) {
			entriesByIndex.put(indexInTable, entry);
		}

		PlaceholderVirtualBaseTableEntry getEntryByIndexInTable(int indexInTable) {
			return entriesByIndex.get(indexInTable);
		}

		PlaceholderVirtualBaseTableEntry getEntryByName(String nameParam) {
			for (Entry<Integer, PlaceholderVirtualBaseTableEntry> entry : entriesByIndex
					.entrySet()) {
				if (nameParam.equals(
					entry.getValue().getVirtualBaseClass().getBaseClassType().getName())) {
					return entry.getValue();
				}
			}
			return null;
		}
	}

}
