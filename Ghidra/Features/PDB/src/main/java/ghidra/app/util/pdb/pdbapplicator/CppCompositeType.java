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

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.SymbolPath;
import ghidra.app.util.bin.format.pdb.*;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.app.util.pdb.classtype.*;
import ghidra.program.model.data.*;
import ghidra.program.model.gclass.ClassID;
import ghidra.program.model.gclass.ClassUtils;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Notional C++ Class Type. Much work has yet to be done with this class.  For instance, the plan
 * is to continue to break this class up into smaller self-contained classes.
 */
public class CppCompositeType {

	private static final String SELF_BASE_COMMENT = "Self Base";
	private static final String BASE_COMMENT = "Base";
	private static final String VIRTUAL_BASE_COMMENT = "Virtual Base";
	private static final String VIRTUAL_BASE_SPECULATIVE_COMMENT =
		"Virtual Base - Speculative Placement";

	private boolean isFinal;
	private ClassKey classKey;
	private String className; // String for now.
	private String mangledName;
	private int size;
	private SymbolPath symbolPath;
	private CategoryPath categoryPath;
	private ClassID myId;

	private CategoryPath baseCategoryPath;
	private CategoryPath internalsCategoryPath;
	private Composite composite;
	private Composite selfBaseType;

	private String summarizedClassVxtPtrInfo;

	// Order matters for both base classes and members for class layout.  Members get offsets,
	//  which helps for those, but layout algorithms usually utilize order.
	private List<DirectLayoutBaseClass> directLayoutBaseClasses;
	private List<VirtualLayoutBaseClass> virtualLayoutBaseClasses;
	private List<DirectVirtualLayoutBaseClass> directVirtualLayoutBaseClasses;
	private List<IndirectVirtualLayoutBaseClass> indirectVirtualLayoutBaseClasses;

	private TreeMap<Long, Pointer> vftPtrTypeByOffset;
	private List<AbstractMember> myMembers;
	private List<Member> layoutMembers;

	private static record VirtualFunctionInfo(Integer tableOffset, Integer thisAdjuster,
			SymbolPath name, FunctionDefinition definition) {}

	private List<VirtualFunctionInfo> virtualFunctionInfo;

	//----

	private List<SyntacticBaseClass> syntacticBaseClasses;

	//==============================================================================================
	//==============================================================================================
	// Data used for laying out the class

	/**
	 * Holds the offset of the VftPtr allocated by this class; is null if it is sharing a VftPtr
	 * of a base class or if one is not needed
	 */
	private Long myVftPtrOffset;
	/**
	 * Holds the offset of the VbtPtr allocated by this class; is null if it is sharing a VbtPtr
	 * of a base class or if one is not needed.
	 */
	private Long myVbtPtrOffset;

	/**
	 * Holds the offset of the VftPtr used by this class, whether allocated by this class or
	 * found in a parent class; null if doesn't use a VftPtr
	 */
	private Long mainVftPtrOffset;
	/**
	 * Holds the offset of the VbtPtr used by this class, whether allocated by this class or
	 * found in a parent class; null if doesn't use a VbtPtr
	 */
	private Long mainVbtPtrOffset;

	/**
	 * Holds the main Vft for this class
	 */
	private VirtualFunctionTable mainVft;

	/**
	 * Holds the main Vbt for this class
	 */
	private VirtualBaseTable mainVbt;

	/**
	 * Value during processing to indicate whether this class has a zero-sized base
	 */
	private boolean hasZeroBaseSize;

	/**
	 * Hold the depth-first traversal occurrence of virtual bases.  See more detail in algorithm
	 * that generates this non-perfect information
	 */
	private LinkedHashMap<ClassID, List<ClassID>> depthFirstVirtualBases;

	private List<Member> layoutVftPtrMembers;
	private List<Member> layoutVbtPtrMembers;

	private Map<Long, OwnerParentage> vftTableIdByOffset; // possibly future use
	private Map<OwnerParentage, Long> vftOffsetByTableId; // possibly future use
	private Map<Long, OwnerParentage> vbtTableIdByOffset; //we use this one
	private Map<OwnerParentage, Long> vbtOffsetByTableId; // possibly future use

	private TreeMap<ClassID, Long> baseOffsetById;

	//==============================================================================================
	//==============================================================================================
	// Data used for analyzing Vxts and their parentage

	private TreeSet<VxtPtrInfo> propagatedSelfBaseVfts;
	private TreeSet<VxtPtrInfo> propagatedSelfBaseVbts;
	private TreeSet<VxtPtrInfo> propagatedDirectVirtualBaseVfts;
	private TreeSet<VxtPtrInfo> propagatedDirectVirtualBaseVbts;
	private TreeSet<VxtPtrInfo> propagatededIndirectVirtualBaseVfts;
	private TreeSet<VxtPtrInfo> propagatedIndirectVirtualBaseVbts;
	private TreeMap<Long, VxtPtrInfo> finalVftPtrInfoByOffset;
	private TreeMap<Long, VxtPtrInfo> finalVbtPtrInfoByOffset;
	private TreeMap<Long, VXT> finalVftByOffset;
	private TreeMap<Long, VXT> finalVbtByOffset;

	//==============================================================================================
	//==============================================================================================
	public CppCompositeType(CategoryPath baseCategoryPath, SymbolPath symbolPath,
			Composite composite, String mangledName) {
		Objects.requireNonNull(symbolPath, "symbolPath may not be null");
		Objects.requireNonNull(composite, "composite may not be null");

		isFinal = false;
		classKey = ClassKey.UNKNOWN;
		this.baseCategoryPath = baseCategoryPath;
		this.symbolPath = symbolPath;
		this.composite = composite;
		this.mangledName = mangledName;
		myId = getClassId(this);
		categoryPath = new CategoryPath(composite.getCategoryPath(), composite.getName());
		internalsCategoryPath = ClassUtils.getClassInternalsPath(composite);  // eliminate

		directLayoutBaseClasses = new ArrayList<>();
		virtualLayoutBaseClasses = new ArrayList<>();
		directVirtualLayoutBaseClasses = new ArrayList<>();
		indirectVirtualLayoutBaseClasses = new ArrayList<>();
		virtualFunctionInfo = new ArrayList<>();

		vftPtrTypeByOffset = new TreeMap<>();
		myMembers = new ArrayList<>();
		layoutMembers = new ArrayList<>();

		syntacticBaseClasses = new ArrayList<>();
	}

	//==============================================================================================
	/**
	 * Method to add a direct base class for this class.  Does not include attributes...
	 * this method is suitable for testing
	 * @param comp the base composite
	 * @param baseClassType the base class type
	 * @param offset the offset
	 * @throws PdbException upon issue with the base not being suitable
	 */
	public void addDirectBaseClass(Composite comp, CppCompositeType baseClassType, int offset)
			throws PdbException {
		addDirectBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN, offset);
	}

	/**
	 * Method to add a direct base class for this class
	 * @param comp the base composite
	 * @param baseClassType the base class type
	 * @param attributes the attributes of the base class
	 * @param offset the offset
	 * @throws PdbException upon issue with the base not being suitable
	 */
	public void addDirectBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int offset) throws PdbException {
		validateBaseClass(baseClassType);
		DirectLayoutBaseClass base =
			new DirectLayoutBaseClass(comp, baseClassType, attributes, offset);
		directLayoutBaseClasses.add(base);
	}

	/**
	 * Method to add a direct virtual base class for this class.  Does not include attributes...
	 * this method is suitable for testing
	 * @param comp the base composite
	 * @param baseClassType the base class type
	 * @param basePointerOffset the offset of the vbtptr within the class that specifies where this
	 * base is located within the class
	 * @param vbptr the vbptr type
	 * @param offsetFromVbt the offset into the vbt that specifies where this base is located
	 * within the class
	 * @throws PdbException upon issue with the base not being suitable
	 */
	public void addDirectVirtualBaseClass(Composite comp, CppCompositeType baseClassType,
			int basePointerOffset, DataType vbptr, int offsetFromVbt) throws PdbException {
		addDirectVirtualBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN,
			basePointerOffset, vbptr, offsetFromVbt);
	}

	/**
	 * Method to add a direct virtual base class for this class
	 * @param comp the base composite
	 * @param baseClassType the base class type
	 * @param attributes the attributes of the base class
	 * @param basePointerOffset the offset of the vbtptr within the class that specifies where this
	 * base is located within the class
	 * @param vbptr the vbptr type
	 * @param offsetFromVbt the offset into the vbt that specifies where this base is located
	 * within the class
	 * @throws PdbException upon issue with the base not being suitable
	 */
	public void addDirectVirtualBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int basePointerOffset, DataType vbptr,
			int offsetFromVbt) throws PdbException {
		validateBaseClass(baseClassType);
		DirectVirtualLayoutBaseClass base =
			new DirectVirtualLayoutBaseClass(comp, baseClassType, attributes, basePointerOffset,
				vbptr, offsetFromVbt);
		directVirtualLayoutBaseClasses.add(base);
		virtualLayoutBaseClasses.add(base);
	}

	/**
	 * Method to add an indirect virtual base class for this class.  Does not include attributes...
	 * this method is suitable for testing
	 * @param comp the base composite
	 * @param baseClassType the base class type
	 * @param basePointerOffset the offset of the vbtptr within the class that specifies where this
	 * base is located within the class
	 * @param vbptr the vbptr type
	 * @param offsetFromVbt the offset into the vbt that specifies where this base is located
	 * within the class
	 * @throws PdbException upon issue with the base not being suitable
	 */
	public void addIndirectVirtualBaseClass(Composite comp, CppCompositeType baseClassType,
			int basePointerOffset, DataType vbptr, int offsetFromVbt) throws PdbException {
		addIndirectVirtualBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN,
			basePointerOffset, vbptr, offsetFromVbt);
	}

	/**
	 * Method to add an indirect virtual base class for this class
	 * @param comp the base composite
	 * @param baseClassType the base class type
	 * @param attributes the attributes of the base class
	 * @param basePointerOffset the offset of the vbtptr within the class that specifies where this
	 * base is located within the class
	 * @param vbptr the vbptr type
	 * @param offsetFromVbt the offset into the vbt that specifies where this base is located
	 * within the class
	 * @throws PdbException upon issue with the base not being suitable
	 */
	public void addIndirectVirtualBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int basePointerOffset, DataType vbptr,
			int offsetFromVbt) throws PdbException {
		validateBaseClass(baseClassType);
		IndirectVirtualLayoutBaseClass base = new IndirectVirtualLayoutBaseClass(comp,
			baseClassType, attributes, basePointerOffset, vbptr, offsetFromVbt);
		indirectVirtualLayoutBaseClasses.add(base);
		virtualLayoutBaseClasses.add(base);
	}

	/**
	 * Method for user to specify a location and type of a virtual function table pointer (from PDB)
	 * @param ptrType the pointer data type
	 * @param offset the offset
	 */
	public void addVirtualFunctionTablePointer(Pointer ptrType, int offset) {
		vftPtrTypeByOffset.put((long) offset, ptrType);
	}

	/**
	 * Method for adding a member to this type, to include a comment, but no attributes parameter
	 * @param memberName member name
	 * @param dataType data type of member
	 * @param isFlexibleArray {@code true} if member is a flexible array
	 * @param offset offset of the member
	 * @param comment comment for the member
	 */
	public void addMember(String memberName, DataType dataType, boolean isFlexibleArray, int offset,
			String comment) {
		addMember(memberName, dataType, isFlexibleArray, ClassFieldAttributes.UNKNOWN, offset,
			comment);
	}

	/**
	 * Method for adding a member to this type; no attributes or comment parameters
	 * @param memberName member name
	 * @param dataType data type of member
	 * @param isFlexibleArray {@code true} if member is a flexible array
	 * @param offset offset of the member
	 */
	public void addMember(String memberName, DataType dataType, boolean isFlexibleArray,
			int offset) {
		addMember(memberName, dataType, isFlexibleArray, ClassFieldAttributes.UNKNOWN, offset,
			null);
	}

	/**
	 * Method for adding a member to this type; includes attributes, but no comment parameter
	 * @param memberName member name
	 * @param dataType data type of member
	 * @param isFlexibleArray {@code true} if member is a flexible array
	 * @param attributes the attributes for the member
	 * @param offset offset of the member
	 */
	public void addMember(String memberName, DataType dataType, boolean isFlexibleArray,
			ClassFieldAttributes attributes, int offset) {
		Member newMember = new Member(memberName, dataType, isFlexibleArray, attributes, offset);
		myMembers.add(newMember);
		addMember(layoutMembers, newMember);
	}

	/**
	 * Method for adding a member to this type, to include a attributes and comment
	 * @param memberName member name
	 * @param dataType data type of member
	 * @param isFlexibleArray {@code true} if member is a flexible array
	 * @param attributes the attributes for the member
	 * @param offset offset of the member
	 * @param comment comment for the member
	 */
	public void addMember(String memberName, DataType dataType, boolean isFlexibleArray,
			ClassFieldAttributes attributes, int offset, String comment) {
		Member newMember =
			new Member(memberName, dataType, isFlexibleArray, attributes, offset, comment);
		myMembers.add(newMember);
		addMember(layoutMembers, newMember);
	}

	/**
	 * Method for adding a virtual method to this type
	 * @param thisAdjuster the this-adjustor offset
	 * @param tableOffset virtual function table offset
	 * @param name function name
	 * @param definition function definition
	 */
	public void addVirtualMethod(int thisAdjuster, int tableOffset, SymbolPath name,
			FunctionDefinition definition) {
		VirtualFunctionInfo info =
			new VirtualFunctionInfo(tableOffset, thisAdjuster, name, definition);
		virtualFunctionInfo.add(info);
	}

	/**
	 * Method to perform class layout from the user specified information.  Note that all
	 * dependency classes (parents, etc.) must have had their like-processing performed
	 * @param layoutOptions the options
	 * @param vxtManager the VxtManager
	 * @param monitor the TaskMonitor
	 * @throws PdbException upon issue performing the layout
	 * @throws CancelledException upon user cancellation
	 */
	public void createLayout(ObjectOrientedClassLayout layoutOptions, MsftVxtManager vxtManager,
			TaskMonitor monitor) throws PdbException, CancelledException {
		switch (layoutOptions) {
			case MEMBERS_ONLY:
				createMembersOnlyClassLayout(monitor);
				break;
			case CLASS_HIERARCHY:
				createHierarchicalClassLayout(vxtManager, monitor);
				// Next line for developer testing cfb432
				//System.out.print(summarizedClassVxtPtrInfo);
				break;
		}
	}

	/**
	 * Method to set whether the class is specified as "final" (sealed)
	 * @param isFinal {@code true} if final
	 */
	public void setFinal(boolean isFinal) {
		this.isFinal = isFinal;
	}

	/**
	 * Returns whether the class was marked "final"
	 * @return {@code true} if final
	 */
	public boolean isFinal() {
		return isFinal;
	}

	/**
	 * Method to specify the composite has a "class" tag
	 */
	public void setClass() {
		classKey = ClassKey.CLASS;
	}

	/**
	 * Method to specify the composite has a "struct" tag
	 */
	public void setStruct() {
		classKey = ClassKey.STRUCT;
	}

	/**
	 * Method to specify the composite has a "union" tag
	 */
	public void setUnion() {
		classKey = ClassKey.UNION;
	}

	/**
	 * Returns the key (i.e., class, struct, union) for this composite
	 * @return the key
	 */
	public ClassKey getKey() {
		return classKey;
	}

	/**
	 * Returns the default access of the type
	 * @return the default access
	 */
	public Access getDefaultAccess() {
		return ClassKey.CLASS.equals(classKey) ? Access.PRIVATE : Access.PUBLIC;
	}

	/**
	 * Method to set the name of the composite
	 * @param className the name
	 */
	public void setName(String className) {
		this.className = className;
	}

	/**
	 * Returns the name of this composite
	 * @return the name
	 */
	public String getName() {
		return className;
	}

	/**
	 * Returns the DataTypePath of the composite
	 * @return the DataTypePath
	 */
	public DataTypePath getDataTypePath() {
		return composite.getDataTypePath();
	}

	/**
	 * Method to set the mangled name of this composite type
	 * @param mangledName the mangled name
	 */
	public void setMangledName(String mangledName) {
		this.mangledName = mangledName;
	}

	/**
	 * Returns the mangled name of this composite
	 * @return the mangled name; can be null if not initialized by the user
	 */
	public String getMangledName() {
		return mangledName;
	}

	/**
	 * Method to set the size of this composite
	 * @param size the size
	 */
	public void setSize(int size) {
		this.size = size;
	}

	/**
	 * Returns the specified composite size that was set by the user
	 * @return the size
	 */
	public int getSize() {
		return size;
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

	//==============================================================================================
	/**
	 * Returns the SymbolPath name of this class
	 * @return the SymbolPath
	 */
	public SymbolPath getSymbolPath() {
		return symbolPath;
	}

	/**
	 * Returns the ClassID for this class
	 * @return the class id
	 */
	public ClassID getClassId() {
		return myId;
	}

	/**
	 * Returns the class composite as a full class layout
	 * @return the composite
	 */
	public Composite getComposite() {
		return composite;
	}

	/**
	 * Returns the "self-base" composite for this class.  When a separate self base is not
	 * needed for this class, the composite is the same as the layout composite returned by
	 * {@link #getComposite()}
	 * @return the self-base composite
	 */
	public Composite getSelfBaseType() {
		return selfBaseType;
	}

	/**
	 * Returns the CategoryPath of this composite
	 * @return the CategoryPath
	 */
	public CategoryPath getCategoryPath() {
		return categoryPath;
	}

	// TODO: move to ClassUtils?
	/**
	 * Returns the "internals" CategoryPath of this composite
	 * @return the CategoryPath
	 */
	public CategoryPath getInternalsCategoryPath() {
		return internalsCategoryPath;
	}

	/**
	 * Return developer VxtPtr summary for this class
	 * @return the summary
	 */
	String getSummarizedClassVxtPtrInfo() {
		return summarizedClassVxtPtrInfo;
	}

	/**
	 * Create DataTypePath of self base of this class
	 * @param baseName the
	 * @return the data type path
	 */
	public DataTypePath getSelfBaseDataTypePath(String baseName) {
		return new DataTypePath(getInternalsCategoryPath(), baseName);
	}

	/**
	 * Create DataTypePath of VBTable.  Currently using the offset of the vbptr, but that might
	 *  change if/when we come up with better naming (like inheritance naming)
	 * @param offset offset of the vbptr
	 * @return the data type path
	 */
	public DataTypePath getVBTableDataTypePath(int offset) {
		return new DataTypePath(getInternalsCategoryPath(), String.format("Vbtable_%08x", offset));
	}

	/**
	 * Create DataTypePath of VFTable.  Currently using the offset of the vfptr, but that might
	 *  change if/when we come up with better naming (like inheritance naming)
	 * @param offset offset of the vfptr
	 * @return the data type path
	 */
	public DataTypePath getVFTableDataTypePath(int offset) {
		return new DataTypePath(getInternalsCategoryPath(), String.format("Vftable_%08x", offset));
	}

	//==============================================================================================
	//==============================================================================================
	/**
	 * Method to validate a base class as being suitable as a base
	 * @param baseClassType the base class type
	 * @throws PdbException if not suitable
	 */
	private static void validateBaseClass(CppCompositeType baseClassType) throws PdbException {
		if (baseClassType.isFinal) {
			throw new PdbException("Cannot inherit base class marked final.");
		}
	}

	/**
	 * Underlying method for adding a member to the class
	 * @param members the members list
	 * @param newMember the new member to add to the list
	 */
	private void addMember(List<Member> members, Member newMember) {
		members.add(newMember);
	}

	//==============================================================================================
	//==============================================================================================

	// NOTE: Need to investigate the usefulness of the following methods and types from long ago

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
	//==============================================================================================

	/**
	 * Returns the DataTypePath for the specified CppCompositeType
	 * @param cppType the type
	 * @return the data type path
	 */
	private static DataTypePath createSelfBaseCategoryPath(CppCompositeType cppType) {
		return cppType.getSelfBaseDataTypePath(cppType.getComposite().getName());
	}

	/**
	 * Generates a class id for the CPP type specified
	 * @param cpp the CPP type
	 * @return the class id
	 */
	private static ClassID getClassId(CppCompositeType cpp) {
		return new ClassID(cpp.baseCategoryPath, cpp.getSymbolPath());
	}

	//==============================================================================================
	//==============================================================================================
	/**
	 * Validates the mangled name against the class key
	 * @param mangledCompositeTypeName the mangled name
	 * @param key the key
	 * @return {@code true} if passed validation
	 */
	static boolean validateMangledCompositeName(String mangledCompositeTypeName, ClassKey key) {
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
				if ((key.compareTo(ClassKey.UNION) != 0) &&
					(key.compareTo(ClassKey.UNKNOWN) != 0)) {
					PdbLog.message("Warning: Mismatched complex type 'T' for " + key);
				}
				break;
			case 'U':
				if ((key.compareTo(ClassKey.STRUCT) != 0) &&
					(key.compareTo(ClassKey.UNKNOWN) != 0)) {
					PdbLog.message("Warning: Mismatched complex type 'U' for " + key);
				}
				break;
			case 'V':
				if ((key.compareTo(ClassKey.CLASS) != 0) &&
					(key.compareTo(ClassKey.UNKNOWN) != 0)) {
					PdbLog.message("Warning: Mismatched complex type 'V' for " + key);
				}
				break;
			default:
				PdbLog.message("Not composite");
				return false;
		}
		return true;

	}

	/**
	 * Method to do some validation of the class parameters prior to trying to the user trying
	 * to construct or use the class
	 * @return {@code true} if validation passed
	 */
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

	//==============================================================================================
	//==============================================================================================

	private TreeSet<VxtPtrInfo> getPropagatedSelfBaseVfts() {
		return propagatedSelfBaseVfts;
	}

	private TreeSet<VxtPtrInfo> getPropagatedSelfBaseVbts() {
		return propagatedSelfBaseVbts;
	}

	private TreeSet<VxtPtrInfo> getPropagatedDirectVirtualBaseVfts() {
		return propagatedDirectVirtualBaseVfts;
	}

	private TreeSet<VxtPtrInfo> getPropagatedDirectVirtualBaseVbts() {
		return propagatedDirectVirtualBaseVbts;
	}

	private TreeSet<VxtPtrInfo> getPropagatedIndirectVirtualBaseVfts() {
		return propagatededIndirectVirtualBaseVfts;
	}

	private TreeSet<VxtPtrInfo> getPropagatedIndirectVirtualBaseVbts() {
		return propagatedIndirectVirtualBaseVbts;
	}

	//==============================================================================================
	//==============================================================================================
	private void createHierarchicalClassLayout(MsftVxtManager vxtManager, TaskMonitor monitor)
			throws PdbException, CancelledException {

		initLayoutAlgorithmData();

		findDirectBaseVxtPtrs(vxtManager);

		findOrAllocateMainVftPtr(vxtManager);
		findOrAllocateMainVbtPtr(vxtManager);

		createClassLayout(vxtManager, monitor);

		finalizeAllVxtParentage();

	}

	/**
	 * Initializes data for class layout and vxtptr information
	 */
	private void initLayoutAlgorithmData() {

		//======
		// Data used for laying out the class

		layoutVftPtrMembers = new ArrayList<>();
		layoutVbtPtrMembers = new ArrayList<>();

		vftTableIdByOffset = new HashMap<>();
		vftOffsetByTableId = new HashMap<>();
		vbtTableIdByOffset = new HashMap<>();
		vbtOffsetByTableId = new HashMap<>();

		baseOffsetById = new TreeMap<>();

		//======
		// Data used for analyzing Vxts and their parentage

		propagatedSelfBaseVfts = new TreeSet<>();
		propagatedSelfBaseVbts = new TreeSet<>();
		propagatedDirectVirtualBaseVfts = new TreeSet<>();
		propagatedDirectVirtualBaseVbts = new TreeSet<>();
		propagatededIndirectVirtualBaseVfts = new TreeSet<>();
		propagatedIndirectVirtualBaseVbts = new TreeSet<>();
		finalVftPtrInfoByOffset = new TreeMap<>();
		finalVbtPtrInfoByOffset = new TreeMap<>();
		finalVftByOffset = new TreeMap<>();
		finalVbtByOffset = new TreeMap<>();
	}

	/**
	 * Determines final parentage information for each vxt.  This information includes full
	 * parentage as well as a shortened version similar to the MSFT mangled scheme  (results not
	 * 100%... needs more work)
	 */
	private void finalizeAllVxtParentage() {

		// Now consolidate virtual indirects (can we use some of what is in MsftVxtManager in the
		//  future (move the node stuff to VxtManager)?

		PNode vbtChildToParentRoot = new PNode(null);
		PNode vbtParentToChildRoot = new PNode(null);
		PNode vftChildToParentRoot = new PNode(null);
		PNode vftParentToChildRoot = new PNode(null);
		PNode childToParentNode;
		PNode parentToChildNode;

		for (VxtPtrInfo info : finalVftPtrInfoByOffset.values()) {
			List<ClassID> parentage = info.parentage();
			childToParentNode = vftChildToParentRoot;
			parentToChildNode = vftParentToChildRoot;
			for (ClassID id : parentage) {
				String name = id.getSymbolPath().toString();
				childToParentNode.incrementPathCount();
				childToParentNode = childToParentNode.getOrAddBranch(name);
			}
			for (ClassID id : parentage.reversed()) {
				String name = id.getSymbolPath().toString();
				parentToChildNode.incrementPathCount();
				parentToChildNode = parentToChildNode.getOrAddBranch(name);
			}
		}
		for (VxtPtrInfo info : finalVbtPtrInfoByOffset.values()) {
			List<ClassID> parentage = info.parentage();
			childToParentNode = vbtChildToParentRoot;
			parentToChildNode = vbtParentToChildRoot;
			for (ClassID id : parentage) {
				String name = id.getSymbolPath().toString();
				childToParentNode.incrementPathCount();
				childToParentNode = childToParentNode.getOrAddBranch(name);
			}
			for (ClassID id : parentage.reversed()) {
				String name = id.getSymbolPath().toString();
				parentToChildNode.incrementPathCount();
				parentToChildNode = parentToChildNode.getOrAddBranch(name);
			}
		}

		StringBuilder builder = new StringBuilder();
		for (VxtPtrInfo info : finalVftPtrInfoByOffset.values()) {
			List<ClassID> altParentage =
				finalizeVxtPtrParentage(vftChildToParentRoot, vftParentToChildRoot, info);
			builder.append(dumpVxtPtrResult("vft", info, altParentage));

		}
		for (VxtPtrInfo info : finalVbtPtrInfoByOffset.values()) {
			List<ClassID> altParentage =
				finalizeVxtPtrParentage(vbtChildToParentRoot, vbtParentToChildRoot, info);
			builder.append(dumpVxtPtrResult("vbt", info, altParentage));
		}
		if (!builder.isEmpty()) {
			builder.insert(0, String.format("Class: %s\n", getSymbolPath().toString()));
		}
		summarizedClassVxtPtrInfo = builder.toString();
	}

	/**
	 * Finalizes the simplification of parentage for the vxt using the collected tree data
	 * @param childToParentNode the child-to-parent tree root node
	 * @param parentToChildNode the parent-to-child tree root node
	 * @param info the information for this vxt
	 * @return the resultant simplified parentage for the vxt
	 */
	private List<ClassID> finalizeVxtPtrParentage(PNode childToParentNode, PNode parentToChildNode,
			VxtPtrInfo info) {
		List<ClassID> parentage = info.parentage();
		List<ClassID> altParentage = new ArrayList<>();
		String startNode = null;

		for (ClassID id : parentage) {
			String name = id.getSymbolPath().toString();
			childToParentNode = childToParentNode.getBranch(name);
			if (childToParentNode.getPathCount() == 1) {
				startNode = name;
				break;
			}
		}

		// If not null, then look for start; otherwise assume start encountered
		//  (use all nodes)
		boolean foundStart = (startNode == null);
		for (ClassID id : parentage.reversed()) {
			String name = id.getSymbolPath().toString();
			if (name.equals(startNode)) {
				foundStart = true;
			}
			if (parentToChildNode.getPathCount() > 1) {
				if (foundStart) {
					altParentage.addFirst(id);
				}
			}
			else {
				break;
			}
			parentToChildNode = parentToChildNode.getBranch(name);
		}
		return altParentage;
	}

	/**
	 * Creates a String dump presentation of the VxtPtrInfo and alternative parentage
	 * @param vxt either {@code "vft"} or {@code "vbt"} String for the VxtPtrInfo
	 * @param info the VxtPtrInfo
	 * @param altParentage the alternative parentage
	 * @return the String output
	 */
	private String dumpVxtPtrResult(String vxt, VxtPtrInfo info, List<ClassID> altParentage) {
		List<String> r1 = new ArrayList<>();
		for (ClassID id : altParentage.reversed()) {
			String name = id.getSymbolPath().toString();
			r1.add(name);
		}
		List<String> r2 = new ArrayList<>();
		for (ClassID id : info.parentage().reversed()) {
			String name = id.getSymbolPath().toString();
			r2.add(name);
		}
		return String.format("  %4d %s %s\t%s\n", info.finalOffset(), vxt, r1.toString(),
			r2.toString());
	}

	/**
	 * Creates the self-base composite
	 */
	private void createSelfBase() {
		DataTypePath selfBasePath = createSelfBaseCategoryPath(this);
		selfBaseType = new StructureDataType(selfBasePath.getCategoryPath(),
			selfBasePath.getDataTypeName(), 0, composite.getDataTypeManager());
		selfBaseType.setDescription("Base of " + selfBasePath.getDataTypeName());
	}

	/**
	 * Creates a members-only layout (the legacy layout)... excludes C++ class hierarchy and vxts
	 * @param monitor the task monitor
	 * @throws CancelledException upon user cancellation
	 */
	private void createMembersOnlyClassLayout(TaskMonitor monitor) throws CancelledException {
		TreeMap<Long, ClassPdbMember> map = new TreeMap<>();
		for (Member member : layoutMembers) {
			ClassPdbMember classPdbMember =
				new ClassPdbMember(member.getName(), member.getDataType(),
					member.isFlexibleArray(), member.getOffset(), member.getComment());
			map.put((long) member.getOffset(), classPdbMember);
		}
		List<ClassPdbMember> sm = new ArrayList<>(map.values());
		if (!DefaultCompositeMember.applyDataTypeMembers(composite, false, false, size,
			sm, msg -> Msg.warn(this, msg), monitor)) {
			clearComponents(composite);
		}
		selfBaseType = composite;
	}

	/**
	 * Lays out the composite and possible self-base for this class
	 * @param vxtManager the vxtManager
	 * @param monitor the monitor
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException up issue with finding the vbt or assigning offsets to virtual bases
	 */
	private void createClassLayout(MsftVxtManager vxtManager, TaskMonitor monitor)
			throws CancelledException, PdbException {
		List<ClassPdbMember> selfBaseMembers = getSelfBaseClassMembers();
		mainVft = getMainVft(vxtManager);
		if (mainVft != null) {
			updateMainVft();
			for (VXT t : finalVftByOffset.values()) {
				VirtualFunctionTable vft = (VirtualFunctionTable) t;
				updateVftFromSelf(vft);
			}
		}
		if (getNumLayoutVirtualBaseClasses() == 0) {
			if (!DefaultCompositeMember.applyDataTypeMembers(composite, false, false, size,
				selfBaseMembers, msg -> Msg.warn(this, msg), monitor)) {
				clearComponents(composite);
			}
			selfBaseType = composite;
		}
		else {
			createSelfBase();
			if (!DefaultCompositeMember.applyDataTypeMembers(selfBaseType, false, false, 0,
				selfBaseMembers, msg -> Msg.warn(this, msg), monitor)) {
				clearComponents(composite);
			}
			ClassPdbMember directClassPdbMember =
				new ClassPdbMember("", selfBaseType, false, 0, SELF_BASE_COMMENT);

			mainVbt = getMainVbt(vxtManager);
			if (mainVbt != null) {
				updateMainVbt();
				// If there was any updating to do for secondary tables, we would do it here.
				//  Something to consider in the future
//				for (VXT t : finalVbtByOffset.values()) {
//					VirtualBaseTable vbt = (VirtualBaseTable) t;
//					updateVbtFromSelf(vbt);
//				}
			}
			assignVirtualBaseOffsets();

			String baseComment = (mainVbt instanceof ProgramVirtualBaseTable) ? VIRTUAL_BASE_COMMENT
					: VIRTUAL_BASE_SPECULATIVE_COMMENT;
			TreeMap<Long, ClassPdbMember> virtualBasePdbMembers =
				getVirtualBaseClassMembers(baseComment);
			findVirtualBaseVxtPtrs(vxtManager);

			TreeMap<Long, ClassPdbMember> allMembers = new TreeMap<>();
			allMembers.put(0L, directClassPdbMember);
			allMembers.putAll(virtualBasePdbMembers);
			List<ClassPdbMember> am = new ArrayList<>(allMembers.values());

			if (!DefaultCompositeMember.applyDataTypeMembers(composite, false, false, size,
				am, msg -> Msg.warn(this, msg), monitor)) {
				clearComponents(composite);
			}
		}
	}

	// Taken from PdbUtil without change.  Would have had to change access on class PdbUtil and
	//  this ensureSize method to public to make it accessible.  Can revert to using PdbUtil
	//  once we move this new module from Contrib to Features/PDB.
	private final static void clearComponents(Composite composite) {
		if (composite instanceof Structure) {
			((Structure) composite).deleteAll();
		}
		else {
			while (composite.getNumComponents() > 0) {
				composite.delete(0);
			}
		}
	}

	/**
	 * Reports whether the base of this class has zero size
	 * @return {@code true} if has zero size
	 */
	private boolean hasZeroBaseSize() {
		return hasZeroBaseSize;
	}

	/**
	 * Returns the self base class members, including possible direct self bases, vxts, and
	 * regular members
	 * @return the members
	 */
	private List<ClassPdbMember> getSelfBaseClassMembers() {
		// Attempting to use TreeMap to sort with the key being a record of
		//  ByteBitOffset (Long byteOff, int bitOff, int ordinal) {}
		//  so that vxtptrs could get injected properly, but this did not work until the "ordinal"
		//  field was included, but the overall solution still does not work because of the
		//  ordering of records when flattened (as MSFT does them) unions are in play.  In such
		//  cases we might get members at offsets: 0, 4, 8, 12, 14, 16, 20 24, 12, 16, 24, 28, 32
		//  which has a union at offset 12 within this outer type.
		// Thus, we just insert the vxts into the members list that is constructed with
		//  base classes and regular members
		hasZeroBaseSize = true;
		List<ClassPdbMember> members = new ArrayList<>();
		String accumulatedComment = "";
		for (DirectLayoutBaseClass base : directLayoutBaseClasses) {
			CppCompositeType baseComposite = base.getBaseClassType();
			// Cannot do baseComposite.getSelfBaseType().isZeroLength()
			//  or baseComposite.getComposite().isZeroLength()
			if (!baseComposite.hasZeroBaseSize()) {
				hasZeroBaseSize = false;
				String comment = BASE_COMMENT;
				if (!accumulatedComment.isEmpty()) {
					comment += " and previous " + accumulatedComment;
				}
				Composite baseDataType = base.getSelfBaseDataType();
				int offset = base.getOffset();
				// This does not have attributes like "Member" does (consider changes?)
				ClassPdbMember classPdbMember =
					new ClassPdbMember("", baseDataType, false, offset, comment);
				members.add(classPdbMember);
				accumulatedComment = "";
			}
			else {
				// Note that if there is only base and it has zero size, this message will not
				// get output.  Consider where we might notate this case in the structure for
				// an improved result
				String comment =
					"(Empty Base " + base.getDataTypePath().getDataTypeName() + ")";
				accumulatedComment += comment;
			}
		}
		hasZeroBaseSize &= layoutVftPtrMembers.size() == 0;
		hasZeroBaseSize &= layoutVbtPtrMembers.size() == 0;
		hasZeroBaseSize &= layoutMembers.size() == 0;

		for (Member member : layoutMembers) {
			ClassPdbMember classPdbMember =
				new ClassPdbMember(member.getName(), member.getDataType(),
					member.isFlexibleArray(), member.getOffset(), member.getComment());
			members.add(classPdbMember);
		}

		for (Member vftMember : layoutVftPtrMembers) { // not expecting more than one
			ClassPdbMember classPdbMember =
				new ClassPdbMember(vftMember.getName(), vftMember.getDataType(),
					vftMember.isFlexibleArray(), vftMember.getOffset(), vftMember.getComment());
			int vOff = vftMember.getOffset();
			int index = 0;
			for (ClassPdbMember member : members) {
				if (member.getOffset() >= vOff) {
					break;
				}
				index++;
			}
			members.add(index, classPdbMember);
		}
		for (Member vbtMember : layoutVbtPtrMembers) { // not expecting more than one
			ClassPdbMember classPdbMember =
				new ClassPdbMember(vbtMember.getName(), vbtMember.getDataType(),
					vbtMember.isFlexibleArray(), vbtMember.getOffset(), vbtMember.getComment());
			int vOff = vbtMember.getOffset();
			int index = 0;
			for (ClassPdbMember member : members) {
				if (member.getOffset() >= vOff) {
					break;
				}
				index++;
			}
			members.add(index, classPdbMember);
		}
		return members;
	}

	/**
	 * Returns the virtual base class members for our class
	 * @param baseComment the general virtual base class comment to be used
	 * @return the members
	 */
	private TreeMap<Long, ClassPdbMember> getVirtualBaseClassMembers(String baseComment) {
		TreeMap<Long, ClassPdbMember> map = new TreeMap<>();
		String accumulatedComment = "";
		for (VirtualLayoutBaseClass base : virtualLayoutBaseClasses) {
			CppCompositeType baseComposite = base.getBaseClassType();
			ClassID id = baseComposite.getClassId();
			Long offset = baseOffsetById.get(id);
			// Cannot do baseComposite.getSelfBaseType().isZeroLength()
			//  or baseComposite.getComposite().isZeroLength()
			if (!baseComposite.hasZeroBaseSize()) {
				String comment = baseComment;
				if (!accumulatedComment.isEmpty()) {
					comment += " and previous " + accumulatedComment;
				}
				Composite baseDataType = base.getSelfBaseDataType();
				// This does not have attributes
				ClassPdbMember classPdbMember =
					new ClassPdbMember("", baseDataType, false, offset.intValue(), comment);
				map.put(offset, classPdbMember);
				accumulatedComment = "";
			}
			else {
				String comment =
					"(Empty Virtual Base " + base.getDataTypePath().getDataTypeName() + ")";
				accumulatedComment += comment;
			}
		}
		return map;
	}

	/**
	 * Finds all virtual base and virtual function pointers in the hierarchy of this class's
	 *  self base.
	 */
	private void findDirectBaseVxtPtrs(VxtManager vxtManager) {
		for (DirectLayoutBaseClass base : directLayoutBaseClasses) {
			CppCompositeType cppBaseType = base.getBaseClassType();
			ClassID baseId = cppBaseType.getClassId();
			long baseOffset = base.getOffset();
			// Note that if the parent has already had its layout done, it will not have
			//  used the vxtManager that we are passing in here; it will have used whatever
			//  was passed to the layout method for that class
			if (cppBaseType.getPropagatedSelfBaseVfts() != null) {
				for (VxtPtrInfo parentInfo : cppBaseType.getPropagatedSelfBaseVfts()) {
					VxtPtrInfo newInfo =
						createSelfOwnedDirectVxtPtrInfo(parentInfo, baseId, baseOffset);
					updateVft(vxtManager, baseId, newInfo, parentInfo);
					storeVxtInfo(propagatedSelfBaseVfts, finalVftPtrInfoByOffset,
						vftTableIdByOffset,
						vftOffsetByTableId, newInfo);
				}
			}
			if (cppBaseType.getPropagatedSelfBaseVbts() != null) {
				for (VxtPtrInfo parentInfo : cppBaseType.getPropagatedSelfBaseVbts()) {
					VxtPtrInfo newInfo =
						createSelfOwnedDirectVxtPtrInfo(parentInfo, baseId, baseOffset);
					updateVbt(vxtManager, baseId, newInfo, parentInfo);
					storeVxtInfo(propagatedSelfBaseVbts, finalVbtPtrInfoByOffset,
						vbtTableIdByOffset,
						vbtOffsetByTableId, newInfo);
				}
			}
		}
	}

	/**
	 * Finds all virtual base and virtual function pointers in the hierarchy of this class's
	 *  virtual bases.  Gathers results from the accumulation of all "direct" virtual base classes;
	 *  we are not relying on the "indirect" virtual base class information from the PDB.  This
	 *  is done this way so that we can collect parentage information for the pointers.
	 * @throws PdbException upon issue finding base offset
	 */
	private void findVirtualBaseVxtPtrs(MsftVxtManager vxtManager) throws PdbException {
		// Walk direct bases to find vxts of virtual bases.  TODO: also notate all rolled up
		//  virtuals for each direct base.
		for (DirectLayoutBaseClass base : directLayoutBaseClasses) {

			CppCompositeType cppBaseType = base.getBaseClassType();
			ClassID baseId = cppBaseType.getClassId();
			for (VxtPtrInfo info : cppBaseType.getPropagatedDirectVirtualBaseVfts()) {
				VxtPtrInfo newInfo = createSelfOwnedVirtualVxtPtrInfo(info);
				updateVft(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatedDirectVirtualBaseVfts, finalVftPtrInfoByOffset,
					vftTableIdByOffset, vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedDirectVirtualBaseVbts()) {
				VxtPtrInfo newInfo = createSelfOwnedVirtualVxtPtrInfo(info);
				updateVbt(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatedDirectVirtualBaseVbts, finalVbtPtrInfoByOffset,
					vbtTableIdByOffset, vbtOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedIndirectVirtualBaseVfts()) {
				VxtPtrInfo newInfo = createSelfOwnedVirtualVxtPtrInfo(info);
				updateVft(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatededIndirectVirtualBaseVfts, finalVftPtrInfoByOffset,
					vftTableIdByOffset, vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedIndirectVirtualBaseVbts()) {
				VxtPtrInfo newInfo = createSelfOwnedVirtualVxtPtrInfo(info);
				updateVbt(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatedIndirectVirtualBaseVbts, finalVbtPtrInfoByOffset,
					vbtTableIdByOffset, vbtOffsetByTableId, newInfo);
			}
		}

		// This loop is currently purposefully separate from the above; we want to determine if
		//  separate vs. together has bearing on order in the lists that might match layout, etc.
		//  if we didn't have VBT in memory to consult.
		for (DirectVirtualLayoutBaseClass base : directVirtualLayoutBaseClasses) {

			CppCompositeType cppBaseType = base.getBaseClassType();
			ClassID baseId = cppBaseType.getClassId();

			for (VxtPtrInfo info : cppBaseType.getPropagatedSelfBaseVfts()) {
				VxtPtrInfo newInfo = createVirtualOwnedSelfVxtPtrInfo(info, baseId);
				updateVft(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatedDirectVirtualBaseVfts, finalVftPtrInfoByOffset,
					vftTableIdByOffset, vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedSelfBaseVbts()) {
				VxtPtrInfo newInfo = createVirtualOwnedSelfVxtPtrInfo(info, baseId);
				updateVbt(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatedDirectVirtualBaseVbts, finalVbtPtrInfoByOffset,
					vbtTableIdByOffset, vbtOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedDirectVirtualBaseVfts()) {
				VxtPtrInfo newInfo = createVirtualOwnedVirtualVxtPtrInfo(info);
				updateVft(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatededIndirectVirtualBaseVfts, finalVftPtrInfoByOffset,
					vftTableIdByOffset, vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedDirectVirtualBaseVbts()) {
				VxtPtrInfo newInfo = createVirtualOwnedVirtualVxtPtrInfo(info);
				updateVbt(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatedIndirectVirtualBaseVbts, finalVbtPtrInfoByOffset,
					vbtTableIdByOffset, vbtOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedIndirectVirtualBaseVfts()) {
				VxtPtrInfo newInfo = createVirtualOwnedVirtualVxtPtrInfo(info);
				updateVft(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatededIndirectVirtualBaseVfts, finalVftPtrInfoByOffset,
					vftTableIdByOffset, vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedIndirectVirtualBaseVbts()) {
				VxtPtrInfo newInfo = createVirtualOwnedVirtualVxtPtrInfo(info);
				updateVbt(vxtManager, baseId, newInfo, info);
				storeVxtInfo(propagatedIndirectVirtualBaseVbts, finalVbtPtrInfoByOffset,
					vbtTableIdByOffset, vbtOffsetByTableId, newInfo);
			}
		}

	}

	// Note sure what the final information will look like when we are done.  For this stopping
	//  point, this method stores what we currently want to store
	/**
	 * Method to store the propagated and final results of the vxt
	 * @param propagate the propagate tree
	 * @param finalInfo the final info tree
	 * @param tableIdByOffset the table-id-by-offset map
	 * @param offsetByTableId the offset-by-table-id map
	 */
	private void storeVxtInfo(TreeSet<VxtPtrInfo> propagate, TreeMap<Long, VxtPtrInfo> finalInfo,
			Map<Long, OwnerParentage> tableIdByOffset, Map<OwnerParentage, Long> offsetByTableId,
			VxtPtrInfo info) {
		propagate.add(info);
		Long finalOffset = info.finalOffset();
		finalInfo.putIfAbsent(finalOffset, info);
		OwnerParentage op = new OwnerParentage(info.baseId(), info.parentage());
		tableIdByOffset.put(finalOffset, op);
		offsetByTableId.put(op, finalOffset);
	}

	/**
	 * Converts VxtPtrInfo from self-owned direct base for this class
	 * @param baseInfo the vxt info from the base
	 * @param baseId the base id of the base
	 * @param baseOffset the base offset of the base
	 * @return the new VxtPtrInfo for this class
	 */
	private VxtPtrInfo createSelfOwnedDirectVxtPtrInfo(VxtPtrInfo baseInfo, ClassID baseId,
			long baseOffset) {
		Long accumOffset = baseInfo.accumOffset() + baseOffset;
		return new VxtPtrInfo(accumOffset, accumOffset, baseId, updateParentage(baseInfo));
	}

	/**
	 * Converts VxtPtrInfo from self-owned direct or indirect virtual base for this class
	 * @param baseInfo the vxt info from the base
	 * @return the new VxtPtrInfo for this class
	 */
	private VxtPtrInfo createSelfOwnedVirtualVxtPtrInfo(VxtPtrInfo baseInfo) {
		Long accumOffset = baseInfo.accumOffset();
		Long finalOffset = accumOffset + baseOffsetById.get(baseInfo.baseId());
		return new VxtPtrInfo(finalOffset, accumOffset, baseInfo.baseId(),
			updateParentage(baseInfo));
	}

	/**
	 * Converts VxtPtrInfo from virtual-based-owned direct base for this class
	 * @param baseInfo the vxt info from the base
	 * @param baseId the base id of the base
	 * @return the new VxtPtrInfo for this class
	 */
	private VxtPtrInfo createVirtualOwnedSelfVxtPtrInfo(VxtPtrInfo baseInfo, ClassID baseId) {
		Long accumOffset = baseInfo.accumOffset();
		Long finalOffset = accumOffset + baseOffsetById.get(baseId);
		return new VxtPtrInfo(finalOffset, accumOffset, baseId, updateParentage(baseInfo));
	}

	/**
	 * Converts VxtPtrInfo from virtual-based-owned direct or indirect virtual base for this class
	 * @param baseInfo the vxt info from the base
	 * @return the new VxtPtrInfo for this class
	 * @throws PdbException upon issue getting base offset
	 */
	private VxtPtrInfo createVirtualOwnedVirtualVxtPtrInfo(VxtPtrInfo baseInfo)
			throws PdbException {
		Long accumOffset = baseInfo.accumOffset();
		Long baseOffset = baseOffsetById.get(baseInfo.baseId());
		if (baseOffset == null) {
			throw new PdbException("Cannot find base offset");
		}
		Long finalOffset = accumOffset + baseOffset;
		return new VxtPtrInfo(finalOffset, accumOffset, baseInfo.baseId(),
			updateParentage(baseInfo));
	}

	private List<ClassID> updateParentage(VxtPtrInfo info) {
		List<ClassID> newParentage = new ArrayList<>(info.parentage());
		newParentage.add(myId);
		return newParentage;
	}

	/**
	 * Uses the main virtual base table to assign offsets for the virtual bases
	 * @throws PdbException if a virtual base offset cannot be identified
	 */
	private void assignVirtualBaseOffsets() throws PdbException {
		for (VirtualLayoutBaseClass base : virtualLayoutBaseClasses) {
			CppCompositeType cppBaseType = base.getBaseClassType();
			Long baseOffset = mainVbt.getBaseOffset(base.getOffetFromVbt());
			if (baseOffset == null) {
				throw new PdbException("Cannot place base class");
			}
			baseOffset += base.getBasePointerOffset();
			ClassID baseId = cppBaseType.getClassId();
			baseOffsetById.put(baseId, baseOffset);
		}
	}

	/**
	 * Finds or allocates (if needed) the Virtual Function Table "Pointer" within the class
	 * structure
	 */
	private void findOrAllocateMainVftPtr(MsftVxtManager vxtManager) {
		if (propagatedSelfBaseVfts.isEmpty()) {
			if (!vftPtrTypeByOffset.isEmpty()) {
				if (vftPtrTypeByOffset.size() > 1) {
					Msg.warn(this, "Unexpected multiple vfts for " + myId);
				}
				myVftPtrOffset = vftPtrTypeByOffset.firstKey();
				VxtPtrInfo info =
					new VxtPtrInfo(myVftPtrOffset, myVftPtrOffset, myId, List.of(myId));
				VirtualFunctionTable myVft = vxtManager.findVft(myId, info.parentage());
				myVft.setPtrOffsetInClass(info.finalOffset());
				propagatedSelfBaseVfts.add(info);
				finalVftByOffset.put(info.finalOffset(), myVft);
				finalVftPtrInfoByOffset.put(info.accumOffset(), info);
				OwnerParentage op = new OwnerParentage(info.baseId(), info.parentage());
				vftTableIdByOffset.put(info.accumOffset(), op);
				vftOffsetByTableId.put(op, info.accumOffset());
				Member newMember = new Member(ClassUtils.VFPTR, ClassUtils.VXPTR_TYPE, false,
					ClassFieldAttributes.UNKNOWN, myVftPtrOffset.intValue());
				layoutVftPtrMembers.add(newMember);
				myMembers.add(newMember);
			}
		}
		mainVftPtrOffset =
			finalVftPtrInfoByOffset.isEmpty() ? null : finalVftPtrInfoByOffset.firstKey();
	}

	/**
	 * Finds or allocates (if needed) the Virtual Base Table "Pointer" for within the class
	 * structure
	 */
	private void findOrAllocateMainVbtPtr(MsftVxtManager vxtManager) {
		if (propagatedSelfBaseVbts.isEmpty()) { // a pointer might be available in a direct base
			if (!virtualLayoutBaseClasses.isEmpty()) { // there is a need for a main vbtptr
				TreeSet<Long> vbtOffsets = new TreeSet<>();
				for (VirtualLayoutBaseClass base : virtualLayoutBaseClasses) {
					vbtOffsets.add((long) base.getBasePointerOffset());
				}
				if (vbtOffsets.size() > 1) {
					Msg.warn(this, "Unexpected multiple vbts for " + myId);
				}
				Long vbtPtrOffset = vbtOffsets.first();
				if (myVbtPtrOffset != null && vbtPtrOffset != myVbtPtrOffset) {
					Msg.warn(this, "Mismatch vbt location for " + myId);
				}
				VxtPtrInfo info = new VxtPtrInfo(vbtPtrOffset, vbtPtrOffset, myId, List.of(myId));
				VirtualBaseTable myVbt = vxtManager.findVbt(myId, info.parentage());
				myVbt.setPtrOffsetInClass(info.finalOffset());
				propagatedSelfBaseVbts.add(info);
				finalVbtByOffset.put(info.finalOffset(), myVbt);
				finalVbtPtrInfoByOffset.put(info.accumOffset(), info);
				OwnerParentage op = new OwnerParentage(info.baseId(), info.parentage());
				vbtTableIdByOffset.put(info.accumOffset(), op);
				vbtOffsetByTableId.put(op, info.accumOffset());
				myVbtPtrOffset = finalVbtPtrInfoByOffset.firstKey();
				Member newMember = new Member(ClassUtils.VBPTR, ClassUtils.VXPTR_TYPE, false,
					ClassFieldAttributes.UNKNOWN, myVbtPtrOffset.intValue());
				layoutVbtPtrMembers.add(newMember);
				myMembers.add(newMember);
			}
		}
		mainVbtPtrOffset =
			finalVbtPtrInfoByOffset.isEmpty() ? null : finalVbtPtrInfoByOffset.firstKey();
	}

	/**
	 * Adds new entries to the main vftable for this class
	 */
	private void updateMainVft() {
		for (VirtualFunctionInfo vfInfo : virtualFunctionInfo) {
			int tableOffset = vfInfo.tableOffset();
			// we believe this adjuster of 0 is all we want for first direct base
			// -1 signifies not intro
			if (vfInfo.thisAdjuster() == 0 && vfInfo.tableOffset() != -1) {
				mainVft.addEntry(tableOffset, vfInfo.name(), vfInfo.name(),
					new PointerDataType(vfInfo.definition()));
			}
		}
	}

	/**
	 * Updates vftable entries with values from this class that override those of parent classes
	 */
	private VirtualFunctionTable updateVft(VxtManager vxtManager, ClassID baseId, VxtPtrInfo info,
			VxtPtrInfo parentInfo) {
		if (!(vxtManager instanceof MsftVxtManager mvxtManager)) {
			// error
			return null;
		}
		ClassID parentId;
		List<ClassID> parentParentage;
		if (parentInfo == null) {
			parentId = info.baseId();
			List<ClassID> parentage = info.parentage();
			parentParentage = parentage.subList(0, parentage.size() - 1);
		}
		else {
			parentId = baseId;
			parentParentage = parentInfo.parentage();
		}

		Long finalOffset = info.finalOffset();
		VirtualFunctionTable myVft = (VirtualFunctionTable) finalVftByOffset.get(finalOffset);
		if (myVft == null) {
			myVft = mvxtManager.findVft(myId, info.parentage());
			if (myVft == null) {
				return null;
			}
			finalVftByOffset.put(finalOffset, myVft);
		}

		myVft.setPtrOffsetInClass(finalOffset);
		VirtualFunctionTable parentVft =
			mvxtManager.findVft(parentId, parentParentage);

		if (parentVft == null) {
			// this is an error
			return null;
		}

		for (Map.Entry<Integer, VirtualFunctionTableEntry> mapEntry : parentVft
				.getEntriesByTableIndex()
				.entrySet()) {
			int tableOffset = mapEntry.getKey();
			VFTableEntry e = mapEntry.getValue();
			SymbolPath parentOrigPath = e.getOriginalPath();
			SymbolPath parentPath = e.getOverridePath();
			VFTableEntry currentEntry = myVft.getEntry(tableOffset);
			if (currentEntry != null) {
				SymbolPath currentOrigPath = currentEntry.getOriginalPath();
				SymbolPath currentPath = currentEntry.getOverridePath();
				// Note that this check also checks the method name
				if (!parentOrigPath.equals(currentOrigPath)) {
					// problem
				}
				boolean parentOverride = !parentOrigPath.equals(parentPath);
				boolean currentOverride = !currentOrigPath.equals(currentPath);
				if (!currentOverride && parentOverride) {
					myVft.addEntry(tableOffset, parentOrigPath, parentPath, e.getFunctionPointer());
				}
				else if (currentOverride && !parentOverride) {
					myVft.addEntry(tableOffset, currentOrigPath, currentPath,
						e.getFunctionPointer());
				}
				else {
					// maybe order matters?
				}
			}
			else {
				myVft.addEntry(tableOffset, parentOrigPath, parentPath, e.getFunctionPointer());
			}
		}
		return myVft;
	}

	private void updateVftFromSelf(VirtualFunctionTable vft) {
		for (Map.Entry<Integer, VirtualFunctionTableEntry> mapEntry : vft.getEntriesByTableIndex()
				.entrySet()) {
			int tableOffset = mapEntry.getKey();
			VFTableEntry e = mapEntry.getValue();
			SymbolPath origPath = e.getOriginalPath();
			SymbolPath methodPath = e.getOverridePath();
			String methodName = methodPath.getName();
			for (VirtualFunctionInfo vfInfo : virtualFunctionInfo) {
				SymbolPath selfMethodPath = vfInfo.name();
				String selfMethodName = selfMethodPath.getName();
				if (selfMethodName.equals(methodName)) {
					// potential overridden method; just replace path (could be the same)
					methodPath = selfMethodPath;
					break;
				}
			}
			vft.addEntry(tableOffset, origPath, methodPath, e.getFunctionPointer());
		}
	}

	private void updateMainVbt() {
		int numEntries = virtualLayoutBaseClasses.size();
		Integer existingEntries = mainVbt.getNumEntries();
		if (numEntries < existingEntries) {
			// error: silent for now... not sure how we want to deal with this
			return;
		}
		for (VirtualLayoutBaseClass virtualLayoutBaseClass : virtualLayoutBaseClasses) {
			int tableOffset = virtualLayoutBaseClass.getOffetFromVbt();
			// Value in base class is more of an index
			ClassID baseId = virtualLayoutBaseClass.getBaseClassType().getClassId();
			int vbtPtrOffset = virtualLayoutBaseClass.getBasePointerOffset();
			if (vbtPtrOffset != mainVbtPtrOffset) {
				// error
				// ignoring for now... not sure how we want to deal with this
				continue;
			}
			VBTableEntry e = mainVbt.getEntry(tableOffset);
			if (e == null) {
				mainVbt.addEntry(tableOffset, baseId);
			}
			// No need to update an existing entry in base table
		}
	}

	// TODO: Remove?  Believe that only the main VBT should ever possibly get updated.  The others
	//  will only get updated in size when they are the main VBT within those respective base
	//  classes.
	private VirtualBaseTable updateVbt(VxtManager vxtManager, ClassID baseId, VxtPtrInfo info,
			VxtPtrInfo parentInfo) {
		if (!(vxtManager instanceof MsftVxtManager mvxtManager)) {
			// error
			return null;
		}
		ClassID parentId;
		List<ClassID> parentParentage;
		if (parentInfo == null) {
			parentId = info.baseId();
			List<ClassID> parentage = info.parentage();
			parentParentage = parentage.subList(0, parentage.size() - 1);
		}
		else {
			parentId = baseId;
			parentParentage = parentInfo.parentage();
		}

		Long finalOffset = info.finalOffset();
		VirtualBaseTable myVbt = (VirtualBaseTable) finalVbtByOffset.get(finalOffset);
		if (myVbt == null) {
			myVbt = mvxtManager.findVbt(myId, info.parentage());
			if (myVbt == null) {
				return null;
			}
			finalVbtByOffset.put(finalOffset, myVbt);
		}

		myVbt.setPtrOffsetInClass(finalOffset);
		VirtualBaseTable parentVbt =
			mvxtManager.findVbt(parentId, parentParentage);
		if (parentVbt == null) {
			// this is an error
			return null;
		}
		for (Map.Entry<Integer, VirtualBaseTableEntry> mapEntry : parentVbt.getEntriesByTableIndex()
				.entrySet()) {
			int tableOffset = mapEntry.getKey();
			VBTableEntry e = mapEntry.getValue();
			myVbt.addEntry(tableOffset, e.getClassId());
		}

		return myVbt;
	}

	/**
	 * Provides the Virtual Base Table to be used for placing virtual bases of this class
	 * @throws PdbException upon unrecognized vft type
	 */
	private VirtualFunctionTable getMainVft(MsftVxtManager vxtManager) throws PdbException {
		if (!finalVftPtrInfoByOffset.isEmpty()) {
			VxtPtrInfo firstVftPtrInfo = finalVftPtrInfoByOffset.firstEntry().getValue();
			VirtualFunctionTable vft = vxtManager.findPrimaryVft(myId, firstVftPtrInfo.parentage());
			return vft;
			// Following is for consideration for testing without a program:
//				if (vft instanceof ProgramVirtualFunctionTable pvft) {
//					return pvft;
//				}
//				else if (vft instanceof PlaceholderVirtualFunctionTable plvft) {
//					return plvft;
//				}
//				else {
//					throw new PdbException(
//						"VFT type not expected: " + vft.getClass().getSimpleName());
//				}
		}
		return null;
	}

	/**
	 * Provides the Virtual Base Table to be used for placing virtual bases of this class
	 * @throws PdbException upon unrecognized vbt type
	 */
	private VirtualBaseTable getMainVbt(MsftVxtManager vxtManager) throws PdbException {
		if (!finalVbtPtrInfoByOffset.isEmpty()) {
			VxtPtrInfo firstVbtPtrInfo = finalVbtPtrInfoByOffset.firstEntry().getValue();
			VirtualBaseTable vbt = vxtManager.findPrimaryVbt(myId, firstVbtPtrInfo.parentage());
			if (vbt instanceof ProgramVirtualBaseTable pvbt) {
				return pvbt;
			}
			else if (vbt instanceof PlaceholderVirtualBaseTable plvbt) {
				List<VirtualLayoutBaseClass> reorderedVirtualBases = new ArrayList<>();
				for (ClassID bId : depthFirstVirtualBases().keySet()) {
					for (VirtualLayoutBaseClass base : virtualLayoutBaseClasses) {
						CppCompositeType baseType = base.getBaseClassType();
						ClassID id = baseType.getClassId();
						if (id.equals(bId)) {
							reorderedVirtualBases.add(base);
						}
					}
				}
				long off = selfBaseType.getAlignedLength();
				for (VirtualLayoutBaseClass base : reorderedVirtualBases) {
					CppCompositeType baseType = base.getBaseClassType();
					addPlaceholderVirtualBaseTableEntry(plvbt, vxtManager, base, off);
					off += baseType.getSelfBaseType().getAlignedLength();
				}
				return plvbt;
			}
			else {
				if (vbt != null) {
					throw new PdbException(
						"VBT type not expected: " + vbt.getClass().getSimpleName());
				}
			}
		}
		return null;
	}

	private void addPlaceholderVirtualBaseTableEntry(PlaceholderVirtualBaseTable ptable,
			MsftVxtManager vxtManager, VirtualLayoutBaseClass base, long baseOffset) {
		long basePtrOffset = base.getBasePointerOffset();
		if (ptable.getPtrOffsetInClass() != basePtrOffset) {
			// error
			return;
		}
		PlaceholderVirtualBaseTableEntry e = ptable.getEntry(base.getOffetFromVbt());
		if (e != null) {
			e.setOffset(baseOffset);
			return;
		}
		ClassID baseId = base.getBaseClassType().getClassId();
		ptable.setBaseClassOffsetAndId(base.getOffetFromVbt(), baseOffset, baseId);
	}

//	private void addVirtualFunctionTableEntry(MsftVxtManager vxtManager, int offsetInTable,
//			SymbolPath methodPath, FunctionDefinition functionDefinition) throws PdbException {
//		OwnerParentage op = vftTableIdByOffset.get(mainVftPtrOffset);
//		if (op == null) {
//			// error
//			return;
//		}
//		if (vxtManager instanceof MsftVxtManager mvxtManager) {
//			VFTable xtable = mvxtManager.findVft(op.owner(), op.parentage());
//			VirtualFunctionTable vft;
//			if (xtable != null) {
//				if (!(xtable instanceof VirtualFunctionTable myvft)) {
//					// error
//					return;
//				}
//				vft = myvft;
//			}
//			else {
//				vft = new PlaceholderVirtualFunctionTable((ProgramClassID) op.owner(),
//					op.parentage(), mainVftPtrOffset.intValue());
//			}
//			vft.addEntry(offsetInTable, methodPath, new PointerDataType(functionDefinition));
//		}
//	}

	/**
	 * Returns depth-first occurrences of ClassIDs along with their parentage with the assumption
	 * that all direct (non-virtual) base classes occur before direct virtual base classes.
	 * It is also presumed that the list of direct virtual base classes for any class are found
	 * in their definition correct order (though might be interspersed with direct non-virtual
	 * bases in the actual definition)
	 * @return the ClassIDs and corresponding parentages (referred to by their ClassIDs)
	 */
	private LinkedHashMap<ClassID, List<ClassID>> depthFirstVirtualBases() {

		if (depthFirstVirtualBases != null) {
			return depthFirstVirtualBases;
		}
		depthFirstVirtualBases = new LinkedHashMap<>();

		for (DirectLayoutBaseClass base : directLayoutBaseClasses) {
			CppCompositeType bt = base.getBaseClassType();
			LinkedHashMap<ClassID, List<ClassID>> baseResults = bt.depthFirstVirtualBases();
			// It is bad to replace an existing entry: we are counting on the parentage of the
			//  first one that occurs.  Thus, we need to inspect and add them one at a time instead
			//  of using addAll().
			for (Map.Entry<ClassID, List<ClassID>> entry : baseResults.entrySet()) {
				if (!depthFirstVirtualBases.containsKey(entry.getKey())) {
					depthFirstVirtualBases.put(entry.getKey(), entry.getValue());
				}
			}
		}
		// If we have a vbt for this class in memory, we can properly place all virtual (direct
		//  and indirect) for this class.  Problem is if we don't have a vbt in program memory,
		//  the problem cannot be solved appropriately.
		// Problem is that MSFT PDB reports all DirectBases (non-virtual)  first, followed by all
		//  DirectVirtualBases, followed by all IndirectVirtualBases.  But by doing so, they
		//  throw away useful information regarding the order of defined base classes for this
		//  class.  The PDB contents won't distinguish between
		//     class A : B, virtual C
		//       and
		//     class A : virtual C, B
		//  ... but these classes can lay out differently when B has its own virtual class(es).
		// The indirect virtual bases cloud things even further.  The direct virtual bases
		//  and indirect virtual base (we call both of these, collectively, virtual bases) will
		//  have representation in the main vbt for this class, and depending on the definition
		//  hierarchy direct virtual bases can intermingled with the indirect virtual bases.
		// We essentially walk the hierarchy of direct non-virtual bases and direct virtual bases
		//  to craft our own list of indirect virtual bases to try to help with this, and it seems
		//  to help a little.  We only use use the PDB-provided indirect virtual bases for when
		//  finding the offset of the base using the vbt (when we have a real vbt in program
		//  memory).
		// This algorithm is meant to try its best to help when we don't have a vbt in program
		//  memory.
		for (VirtualLayoutBaseClass base : virtualLayoutBaseClasses) {
			CppCompositeType bt = base.getBaseClassType();
			LinkedHashMap<ClassID, List<ClassID>> baseResults = bt.depthFirstVirtualBases();
			// It is bad to replace an existing entry: we are counting on the parentage of the
			//  first one that occurs.  Thus, we need to inspect and add them one at a time instead
			//  of using addAll().
			for (Map.Entry<ClassID, List<ClassID>> entry : baseResults.entrySet()) {
				if (!depthFirstVirtualBases.containsKey(entry.getKey())) {
					depthFirstVirtualBases.put(entry.getKey(), entry.getValue());
				}
			}
		}
		for (DirectVirtualLayoutBaseClass base : directVirtualLayoutBaseClasses) {
			CppCompositeType bt = base.getBaseClassType();
			ClassID baseId = bt.getClassId();
			ArrayList<ClassID> baseParentage = new ArrayList<>(List.of(baseId));
			depthFirstVirtualBases.put(baseId, baseParentage);
		}
		// add self to all parentage
		for (List<ClassID> parentage : depthFirstVirtualBases.values()) {
			parentage.addFirst(myId);
		}
		return depthFirstVirtualBases;
	}

	/**
	 * Class used for collecting owner and parentage information for vxtptrs (and maybe base
	 * classes... in the future).  Used for creating a tree of information that is used for
	 * determining shortened MSFT parentage.
	 */
	private static class PNode {
		private String name;
		private List<PNode> branches;
		private int pathCount;

		private PNode(String name) {
			this.name = name;
			branches = new ArrayList<>();
			pathCount = 0;
		}

		private void incrementPathCount() {
			pathCount++;
		}

		private int getPathCount() {
			return pathCount;
		}

		private PNode getBranch(String branchName) {
			for (PNode node : branches) {
				if (node.name.equals(branchName)) {
					return node;
				}
			}
			return null;
		}

		private PNode getOrAddBranch(String branchName) {
			PNode node = getBranch(branchName);
			if (node != null) {
				return node;
			}
			node = new PNode(branchName);
			branches.add(node);
			return node;
		}

	}

	//==============================================================================================
	//==============================================================================================

	/**
	 * We understand the shallow immutability of records and that the contents of the List are
	 * not used in comparison.  Should we convert from record to class?
	 */
	private record VxtPtrInfo(Long finalOffset, Long accumOffset, ClassID baseId,
			List<ClassID> parentage)
			implements Comparable<VxtPtrInfo> {
		@Override
		public int compareTo(VxtPtrInfo other) {
			int val = Long.compare(finalOffset, other.finalOffset);
			if (val != 0) {
				return val;
			}
			val = Long.compare(accumOffset, other.accumOffset);
			if (val != 0) {
				return val;
			}
			val = baseId.compareTo(other.baseId);
			if (val != 0) {
				return val;
			}
			int sizeComp = parentage.size() - other.parentage.size();
			Iterator<ClassID> iter = parentage.iterator();
			Iterator<ClassID> oiter = other.parentage.iterator();
			while (iter.hasNext() && oiter.hasNext()) {
				ClassID id = iter.next();
				ClassID oid = oiter.next();
				val = id.compareTo(oid);
				if (val != 0) {
					return val;
				}
			}
			return sizeComp;
		}
	}

	//==============================================================================================
	//==============================================================================================

	// NOTE: Methods from long ago that possibly will have some future use

	public void addStaticMember(String memberName, DataType dataType) {
		addStaticMember(memberName, dataType, ClassFieldAttributes.UNKNOWN);
	}

	public void addStaticMember(String memberName, DataType dataType,
			ClassFieldAttributes attributes) {
		myMembers.add(new StaticMember(memberName, dataType, attributes));
	}

	public int getNumLayoutVirtualBaseClasses() {
		return virtualLayoutBaseClasses.size();
	}

	public int getNumSyntacticBaseClasses() {
		return syntacticBaseClasses.size();
	}

	public void addSyntacticBaseClass(Composite comp, CppCompositeType baseClassType)
			throws PdbException {
		addSyntacticBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN);
	}

	public void addSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes) throws PdbException {
		validateBaseClass(baseClassType);
		syntacticBaseClasses.add(new SyntacticBaseClass(comp, baseClassType, attributes));
	}

	public void addDirectSyntacticBaseClass(Composite comp, CppCompositeType baseClassType)
			throws PdbException {
		addDirectSyntacticBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN);
	}

	public void addDirectSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes) throws PdbException {
		validateBaseClass(baseClassType);
		syntacticBaseClasses.add(new DirectSyntacticBaseClass(comp, baseClassType, attributes));
	}

	public void addVirtualSyntacticBaseClass(Composite comp, CppCompositeType baseClassType)
			throws PdbException {
		addVirtualSyntacticBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN);
	}

	public void addVirtualSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes) throws PdbException {
		validateBaseClass(baseClassType);
		syntacticBaseClasses.add(new VirtualSyntacticBaseClass(comp, baseClassType, attributes));
	}

	public void insertSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			int ordinal) throws PdbException {
		insertSyntacticBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN, ordinal);
	}

	public void insertSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int ordinal) throws PdbException {
		validateBaseClass(baseClassType);
		if (ordinal < 0 || ordinal > getNumSyntacticBaseClasses()) {
			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
			throw new PdbException("Invalid base class insertion index.");
		}
		syntacticBaseClasses.add(ordinal, new SyntacticBaseClass(comp, baseClassType, attributes));
	}

	public void insertDirectSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			int ordinal) throws PdbException {
		insertDirectSyntacticBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN, ordinal);
	}

	public void insertDirectSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int ordinal) throws PdbException {
		validateBaseClass(baseClassType);
		if (ordinal < 0 || ordinal > getNumSyntacticBaseClasses()) {
			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
			throw new PdbException("Invalid base class insertion index.");
		}
		syntacticBaseClasses.add(ordinal,
			new DirectSyntacticBaseClass(comp, baseClassType, attributes));
	}

	public void insertVirtualSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			int ordinal) throws PdbException {
		insertVirtualSyntacticBaseClass(comp, baseClassType, ClassFieldAttributes.UNKNOWN, ordinal);
	}

	public void insertVirtualSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
			ClassFieldAttributes attributes, int ordinal) throws PdbException {
		validateBaseClass(baseClassType);
		if (ordinal < 0 || ordinal > getNumSyntacticBaseClasses()) {
			// TODO: Change this to some new Exception type; e.g., ClassTypeException.
			throw new PdbException("Invalid base class insertion index.");
		}
		syntacticBaseClasses.add(ordinal,
			new VirtualSyntacticBaseClass(comp, baseClassType, attributes));
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
	//----------------------------------------------------------------------------------------------
	private abstract class BaseClass {
		// In the future, if CppClassType is a formal DataType, then we want to be able to get
		// an already-formed unique class from the DTM.  There is no reason to have a base
		// class duplicated as individually created components of DirectBaseClasses.
		private Composite comp;
		// Added comp above with hopes of eliminating baseClassType (CppCompositeType) in the
		//  future
		private CppCompositeType baseClassType;
		private ClassFieldAttributes attributes;

		private BaseClass(Composite comp, CppCompositeType baseClassType,
				ClassFieldAttributes attributes) {
			this.comp = comp;
			this.baseClassType = baseClassType;
			this.attributes = attributes;
		}

		Composite getBaseClassComposite() {
			return comp;
		}

		CppCompositeType getBaseClassType() {
			return baseClassType;
		}

		ClassFieldAttributes getAttributes() {
			return attributes;
		}

		DataTypePath getDataTypePath() {
			return baseClassType.getDataTypePath();
		}

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append(attributes);
			builder.append(baseClassType.getName());
			return builder.toString();
		}

		Composite getSelfBaseDataType() {
			CppCompositeType cct = getBaseClassType();
			return ClassUtils.getSelfBaseType(comp);
		}

	}

	//----------------------------------------------------------------------------------------------
	// Syntactic description of base classes.
	//----------------------------------------------------------------------------------------------
	private class SyntacticBaseClass extends BaseClass {
		private SyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
				ClassFieldAttributes attributes) {
			super(comp, baseClassType, attributes);
		}
	}

	private class DirectSyntacticBaseClass extends SyntacticBaseClass {
		private DirectSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
				ClassFieldAttributes attributes) {
			super(comp, baseClassType, attributes);
		}
	}

	private class VirtualSyntacticBaseClass extends SyntacticBaseClass {
		private VirtualSyntacticBaseClass(Composite comp, CppCompositeType baseClassType,
				ClassFieldAttributes attributes) {
			super(comp, baseClassType, attributes);
		}
	}

	//----------------------------------------------------------------------------------------------
	//  Layout description of base classes follow
	//----------------------------------------------------------------------------------------------

	// NOTE: The following types are currently used and need to be evaluated for changes and
	// possibly moved to their own java files

	private abstract class LayoutBaseClass extends BaseClass {
		Structure layout = null;

		LayoutBaseClass(Composite comp, CppCompositeType baseClassType,
				ClassFieldAttributes attributes) {
			super(comp, baseClassType, attributes);
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

		private DirectLayoutBaseClass(Composite comp, CppCompositeType baseClassType,
				ClassFieldAttributes attributes, int offset) {
			super(comp, baseClassType, attributes);
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

		private VirtualLayoutBaseClass(Composite comp, CppCompositeType baseClass,
				ClassFieldAttributes attributes,
				int basePointerOffset, DataType vbptr, int offsetFromVbt) {
			super(comp, baseClass, attributes);
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
		private DirectVirtualLayoutBaseClass(Composite comp, CppCompositeType baseClass,
				ClassFieldAttributes attributes, int basePointerOffset, DataType vbptr,
				int offsetFromVbt) {
			super(comp, baseClass, attributes, basePointerOffset, vbptr, offsetFromVbt);
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
		private IndirectVirtualLayoutBaseClass(Composite comp, CppCompositeType baseClass,
				ClassFieldAttributes attributes, int basePointerOffset, DataType vbptr,
				int offsetFromVbt) {
			super(comp, baseClass, attributes, basePointerOffset, vbptr, offsetFromVbt);
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

}
