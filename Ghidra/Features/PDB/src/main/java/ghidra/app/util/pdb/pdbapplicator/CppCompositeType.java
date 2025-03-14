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
	//private static final String INDIRECT_VIRTUAL_BASE_CLASS_COMMENT = "Indirect Virtual Base Class";

	private boolean isFinal;
	private ClassKey classKey;
	private String className; // String for now.
	private String mangledName;
	private int size;
	private SymbolPath symbolPath;
	private CategoryPath categoryPath;
	private DataTypePath selfBaseDataTypePath;
	private ProgramClassID myId;

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
	// Data used for resolving main vftptr

	/*
	 * Not certain, but think there should only be one Virtual Base Table for a given
	 * class (not counting those for its parents).  However, since VirtualBaseClass and
	 * IndirectVirtualBase class records both have an "offset" for (seemingly) where the
	 * virtual base table point can be located, then there is a chance that different
	 * records for a class could have different values.  This HashMap will is keyed by this
	 * offset, in case we see more than one.  Want to log the fact if more than one value is seen
	 * for a particular hierarchy level.
	 */
	private Map<Long, PlaceholderVirtualBaseTable> placeholderVirtualBaseTables;

	//==============================================================================================
	// Data used for analyzing Vxts and their parentage

	private TreeSet<VxtPtrInfo> propagatedSelfBaseVfts;
	private TreeSet<VxtPtrInfo> propagatedSelfBaseVbts;
	private TreeSet<VxtPtrInfo> propagatedDirectVirtualBaseVfts;
	private TreeSet<VxtPtrInfo> propagatedDirectVirtualBaseVbts;
	private TreeSet<VxtPtrInfo> propagatededIndirectVirtualBaseVfts;
	private TreeSet<VxtPtrInfo> propagatedIndirectVirtualBaseVbts;
	private TreeMap<Long, VxtPtrInfo> finalLayoutVfts;
	private TreeMap<Long, VxtPtrInfo> finalLayoutVbts;

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
		internalsCategoryPath = ClassUtils.getClassInternalsPath(composite);  // eliminate
		selfBaseDataTypePath = ClassUtils.getBaseClassDataTypePath(composite);

		directLayoutBaseClasses = new ArrayList<>();
		virtualLayoutBaseClasses = new ArrayList<>();
		directVirtualLayoutBaseClasses = new ArrayList<>();
		indirectVirtualLayoutBaseClasses = new ArrayList<>();

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
	 * Method for adding a member to this type, to include a attribtues and comment
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
	 * Method to perform class layout from the user specified information.  Note that all
	 * dependency classes (parents, etc.) must have had their like-processing performed
	 * @param layoutOptions the options
	 * @param vxtManager the VxtManager
	 * @param monitor the TaskMonitor
	 * @throws PdbException upon issue performing the layout
	 * @throws CancelledException upon user cancellation
	 */
	public void createLayout(ObjectOrientedClassLayout layoutOptions, VxtManager vxtManager,
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
	public ProgramClassID getClassId() {
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
	private static ProgramClassID getClassId(CppCompositeType cpp) {
		return new ProgramClassID(cpp.baseCategoryPath, cpp.getSymbolPath());
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
	private void createHierarchicalClassLayout(VxtManager vxtManager, TaskMonitor monitor)
			throws PdbException, CancelledException {

		initLayoutAlgorithmData();

		findDirectBaseVxtPtrs();

		findOrAllocateMainVftPtr();
		findOrAllocateMainVbtPtr();

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
		// Data used for resolving main vftptr

		placeholderVirtualBaseTables = new HashMap<>();

		//======
		// Data used for analyzing Vxts and their parentage

		propagatedSelfBaseVfts = new TreeSet<>();
		propagatedSelfBaseVbts = new TreeSet<>();
		propagatedDirectVirtualBaseVfts = new TreeSet<>();
		propagatedDirectVirtualBaseVbts = new TreeSet<>();
		propagatededIndirectVirtualBaseVfts = new TreeSet<>();
		propagatedIndirectVirtualBaseVbts = new TreeSet<>();
		finalLayoutVfts = new TreeMap<>();
		finalLayoutVbts = new TreeMap<>();
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

		for (VxtPtrInfo info : finalLayoutVfts.values()) {
			List<ClassID> parentage = info.parentage();
			childToParentNode = vftChildToParentRoot;
			parentToChildNode = vftParentToChildRoot;
			for (ClassID id : parentage) {
				String name = ((ProgramClassID) id).getSymbolPath().toString();
				childToParentNode.incrementPathCount();
				childToParentNode = childToParentNode.getOrAddBranch(name);
			}
			for (ClassID id : parentage.reversed()) {
				String name = ((ProgramClassID) id).getSymbolPath().toString();
				parentToChildNode.incrementPathCount();
				parentToChildNode = parentToChildNode.getOrAddBranch(name);
			}
		}
		for (VxtPtrInfo info : finalLayoutVbts.values()) {
			List<ClassID> parentage = info.parentage();
			childToParentNode = vbtChildToParentRoot;
			parentToChildNode = vbtParentToChildRoot;
			for (ClassID id : parentage) {
				String name = ((ProgramClassID) id).getSymbolPath().toString();
				childToParentNode.incrementPathCount();
				childToParentNode = childToParentNode.getOrAddBranch(name);
			}
			for (ClassID id : parentage.reversed()) {
				String name = ((ProgramClassID) id).getSymbolPath().toString();
				parentToChildNode.incrementPathCount();
				parentToChildNode = parentToChildNode.getOrAddBranch(name);
			}
		}

		StringBuilder builder = new StringBuilder();
		for (VxtPtrInfo info : finalLayoutVfts.values()) {
			List<ClassID> altParentage =
				finalizeVxtPtrParentage(vftChildToParentRoot, vftParentToChildRoot, info);
			builder.append(dumpVxtPtrResult("vft", info, altParentage));

		}
		for (VxtPtrInfo info : finalLayoutVbts.values()) {
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
			String name = ((ProgramClassID) id).getSymbolPath().toString();
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
			String name = ((ProgramClassID) id).getSymbolPath().toString();
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
			String name = ((ProgramClassID) id).getSymbolPath().toString();
			r1.add(name);
		}
		List<String> r2 = new ArrayList<>();
		for (ClassID id : info.parentage().reversed()) {
			String name = ((ProgramClassID) id).getSymbolPath().toString();
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
	private void createClassLayout(VxtManager vxtManager, TaskMonitor monitor)
			throws CancelledException, PdbException {
		List<ClassPdbMember> selfBaseMembers = getSelfBaseClassMembers();
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
			assignVirtualBaseOffsets();

			String baseComment = (mainVbt instanceof ProgramVirtualBaseTable) ? VIRTUAL_BASE_COMMENT
					: VIRTUAL_BASE_SPECULATIVE_COMMENT;
			TreeMap<Long, ClassPdbMember> virtualBasePdbMembers =
				getVirtualBaseClassMembers(baseComment);
			findVirtualBaseVxtPtrs();

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
	private void findDirectBaseVxtPtrs() {
		for (DirectLayoutBaseClass base : directLayoutBaseClasses) {
			CppCompositeType cppBaseType = base.getBaseClassType();
			ProgramClassID baseId = cppBaseType.getClassId();
			long baseOffset = base.getOffset();
			// Note that if the parent has already had its layout done, it will not have
			//  used the vxtManager that we are passing in here; it will have used whatever
			//  was passed to the layout method for that class
			for (VxtPtrInfo info : cppBaseType.getPropagatedSelfBaseVfts()) {
				VxtPtrInfo newInfo = createSelfOwnedDirectVxtPtrInfo(info, baseId, baseOffset);
				storeVxtInfo(propagatedSelfBaseVfts, finalLayoutVfts, vftTableIdByOffset,
					vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedSelfBaseVbts()) {
				VxtPtrInfo newInfo = createSelfOwnedDirectVxtPtrInfo(info, baseId, baseOffset);
				storeVxtInfo(propagatedSelfBaseVbts, finalLayoutVbts, vbtTableIdByOffset,
					vbtOffsetByTableId, newInfo);
			}
		}
	}

	/**
	 * Finds all virtual base and virtual function pointers in the hierarchy of this class's
	 *  virtual bases.  Gathers results from the accumulation of all "direct" virtual base classes;
	 *  we are not relying on the "indirect" virtual base class information from the PDB.  This
	 *  is done this way so that we can collect parentage information for the pointers.
	 */
	private void findVirtualBaseVxtPtrs() {
		// Walk direct bases to find vxts of virtual bases.  TODO: also notate all rolled up
		//  virtuals for each direct base.
		for (DirectLayoutBaseClass base : directLayoutBaseClasses) {

			CppCompositeType cppBaseType = base.getBaseClassType();

			for (VxtPtrInfo info : cppBaseType.getPropagatedDirectVirtualBaseVfts()) {
				VxtPtrInfo newInfo = createSelfOwnedVirtualVxtPtrInfo(info);
				storeVxtInfo(propagatedDirectVirtualBaseVfts, finalLayoutVfts, vftTableIdByOffset,
					vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedDirectVirtualBaseVbts()) {
				VxtPtrInfo newInfo = createSelfOwnedVirtualVxtPtrInfo(info);
				storeVxtInfo(propagatedDirectVirtualBaseVbts, finalLayoutVbts, vbtTableIdByOffset,
					vbtOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedIndirectVirtualBaseVfts()) {
				VxtPtrInfo newInfo = createSelfOwnedVirtualVxtPtrInfo(info);
				storeVxtInfo(propagatededIndirectVirtualBaseVfts, finalLayoutVfts,
					vftTableIdByOffset, vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedIndirectVirtualBaseVbts()) {
				VxtPtrInfo newInfo = createSelfOwnedVirtualVxtPtrInfo(info);
				storeVxtInfo(propagatedIndirectVirtualBaseVbts, finalLayoutVbts, vbtTableIdByOffset,
					vbtOffsetByTableId, newInfo);
			}
		}

		// This loop is currently purposefully separate from the above; we want to determine if
		//  separate vs. together has bearing on order in the lists that might match layout, etc.
		//  if we didn't have VBT in memory to consult.
		for (DirectVirtualLayoutBaseClass base : directVirtualLayoutBaseClasses) {

			CppCompositeType cppBaseType = base.getBaseClassType();
			ProgramClassID baseId = cppBaseType.getClassId();

			for (VxtPtrInfo info : cppBaseType.getPropagatedSelfBaseVfts()) {
				VxtPtrInfo newInfo = createVirtualOwnedSelfVxtPtrInfo(info, baseId);
				storeVxtInfo(propagatedDirectVirtualBaseVfts, finalLayoutVfts, vftTableIdByOffset,
					vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedSelfBaseVbts()) {
				VxtPtrInfo newInfo = createVirtualOwnedSelfVxtPtrInfo(info, baseId);
				storeVxtInfo(propagatedDirectVirtualBaseVbts, finalLayoutVbts, vbtTableIdByOffset,
					vbtOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedDirectVirtualBaseVfts()) {
				VxtPtrInfo newInfo = createVirtualOwnedVirtualVxtPtrInfo(info);
				storeVxtInfo(propagatededIndirectVirtualBaseVfts, finalLayoutVfts,
					vftTableIdByOffset, vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedDirectVirtualBaseVbts()) {
				VxtPtrInfo newInfo = createVirtualOwnedVirtualVxtPtrInfo(info);
				storeVxtInfo(propagatedIndirectVirtualBaseVbts, finalLayoutVbts, vbtTableIdByOffset,
					vbtOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedIndirectVirtualBaseVfts()) {
				VxtPtrInfo newInfo = createVirtualOwnedVirtualVxtPtrInfo(info);
				storeVxtInfo(propagatededIndirectVirtualBaseVfts, finalLayoutVfts,
					vftTableIdByOffset, vftOffsetByTableId, newInfo);
			}
			for (VxtPtrInfo info : cppBaseType.getPropagatedIndirectVirtualBaseVbts()) {
				VxtPtrInfo newInfo = createVirtualOwnedVirtualVxtPtrInfo(info);
				storeVxtInfo(propagatedIndirectVirtualBaseVbts, finalLayoutVbts, vbtTableIdByOffset,
					vbtOffsetByTableId, newInfo);
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
	 * @param info the vxt ptr info
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
	 */
	private VxtPtrInfo createVirtualOwnedVirtualVxtPtrInfo(VxtPtrInfo baseInfo) {
		Long accumOffset = baseInfo.accumOffset();
		Long finalOffset = accumOffset + baseOffsetById.get(baseInfo.baseId());
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
			ProgramClassID baseId = cppBaseType.getClassId();
			baseOffsetById.put(baseId, baseOffset);
		}
	}

	/**
	 * Finds or allocates (if needed) the Virtual Function Table "Pointer" within the class
	 * structure
	 */
	private void findOrAllocateMainVftPtr() {
		if (propagatedSelfBaseVfts.isEmpty()) {
			if (!vftPtrTypeByOffset.isEmpty()) {
				if (vftPtrTypeByOffset.size() > 1) {
					Msg.warn(this, "Unexpected multiple vfts for " + myId);
				}
				myVftPtrOffset = vftPtrTypeByOffset.firstKey();
				VxtPtrInfo info =
					new VxtPtrInfo(myVftPtrOffset, myVftPtrOffset, myId, List.of(myId));
				propagatedSelfBaseVfts.add(info);
				finalLayoutVfts.put(info.accumOffset(), info);
				OwnerParentage op = new OwnerParentage(info.baseId(), info.parentage());
				vftTableIdByOffset.put(info.accumOffset(), op);
				vftOffsetByTableId.put(op, info.accumOffset());
				Member newMember = new Member(ClassUtils.VFPTR, ClassUtils.VXPTR_TYPE, false,
					ClassFieldAttributes.UNKNOWN, myVftPtrOffset.intValue());
				layoutVftPtrMembers.add(newMember);
				myMembers.add(newMember);

			}
		}
		mainVftPtrOffset = finalLayoutVfts.isEmpty() ? null : finalLayoutVfts.firstKey();
	}

	/**
	 * Finds or allocates (if needed) the Virtual Base Table "Pointer" for within the class
	 * structure
	 */
	private void findOrAllocateMainVbtPtr() {
		if (propagatedSelfBaseVbts.isEmpty()) {
			if (!virtualLayoutBaseClasses.isEmpty()) {
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
				propagatedSelfBaseVbts.add(info);
				finalLayoutVbts.put(info.accumOffset(), info);
				OwnerParentage op = new OwnerParentage(info.baseId(), info.parentage());
				vbtTableIdByOffset.put(info.accumOffset(), op);
				vbtOffsetByTableId.put(op, info.accumOffset());
				myVbtPtrOffset = finalLayoutVbts.firstKey();
				Member newMember = new Member(ClassUtils.VBPTR, ClassUtils.VXPTR_TYPE, false,
					ClassFieldAttributes.UNKNOWN, myVbtPtrOffset.intValue());
				layoutVbtPtrMembers.add(newMember);
				myMembers.add(newMember);
			}
		}
		mainVbtPtrOffset = finalLayoutVbts.isEmpty() ? null : finalLayoutVbts.firstKey();
	}

	/**
	 * Provides the Virtual Base Table to be used for placing virtual bases of this class
	 */
	private VirtualBaseTable getMainVbt(VxtManager vxtManager) throws PdbException {
		VirtualBaseTable vbt = null;
		if (!finalLayoutVbts.isEmpty()) {
			VxtPtrInfo firstVbtPtrInfo = finalLayoutVbts.firstEntry().getValue();
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
			long offset = selfBaseType.getAlignedLength();
			for (VirtualLayoutBaseClass base : reorderedVirtualBases) {
				CppCompositeType baseType = base.getBaseClassType();
				addPlaceholderVirtualBaseTableEntry(vxtManager, base, offset);
				offset += baseType.getSelfBaseType().getAlignedLength();
			}
			if (vxtManager instanceof MsftVxtManager mvxtManager) {
				VBTable table = mvxtManager.findVbt(myId, firstVbtPtrInfo.parentage());
				if (table instanceof ProgramVirtualBaseTable pvbt) {
					return pvbt;
				}
			}
			vbt = placeholderVirtualBaseTables.get(mainVbtPtrOffset);
		}
		return vbt;
	}

	//----------------------------------------------------------------------------------------------
	//----------------------------------------------------------------------------------------------
	// used by find main vbt (probably should evaluate for cleanup)
	private void addPlaceholderVirtualBaseTableEntry(VxtManager vxtManager,
			VirtualLayoutBaseClass base, Long baseOffset) throws PdbException {

		long index = base.getBasePointerOffset();
		OwnerParentage op = vbtTableIdByOffset.get(index);
		if (op == null) {
			// error
			return;
		}
		if (vxtManager instanceof MsftVxtManager mvxtManager) {
			VBTable xtable = mvxtManager.findVbt(op.owner(), op.parentage());
			if (xtable == null) {
				int entrySize =
					composite.getDataTypeManager().getDataOrganization().getIntegerSize();
				PlaceholderVirtualBaseTable newTable =
					new PlaceholderVirtualBaseTable(op.owner(), op.parentage(), entrySize);
				xtable = newTable;
				placeholderVirtualBaseTables.put(index, newTable);
			}
			if (xtable instanceof PlaceholderVirtualBaseTable ptable) {
				VBTableEntry e = ptable.getBase(base.getOffetFromVbt());
				if (e != null) {
					return;
				}
				ClassID baseId = base.getBaseClassType().getClassId();
				ptable.setBaseClassOffsetAndId(base.getOffetFromVbt(), baseOffset, baseId);
			}
		}
		else {
			PlaceholderVirtualBaseTable ptable = placeholderVirtualBaseTables.get(index);
			if (ptable == null) {
				int entrySize =
					composite.getDataTypeManager().getDataOrganization().getIntegerSize();
				ptable = new PlaceholderVirtualBaseTable(op.owner(), op.parentage(), entrySize);
				placeholderVirtualBaseTables.put(index, ptable);
			}
			VBTableEntry e = ptable.getBase(base.getOffetFromVbt());
			if (e != null) {
				return;
			}
			ClassID baseId = base.getBaseClassType().getClassId();
			ptable.setBaseClassOffsetAndId(base.getOffetFromVbt(), baseOffset, baseId);
		}
	}

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
	 * Record holding owner and parentage using ClassIDs.  These can be used for vxtptrs and
	 * (possibly) also for base class info
	 */
	private record OwnerParentage(ClassID owner, List<ClassID> parentage) {}

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
