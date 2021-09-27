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
//DO NOT RUN. THIS IS NOT A SCRIPT! THIS IS A CLASS THAT IS USED BY SCRIPTS. 
package classrecovery;

import java.util.*;
import java.util.Map.Entry;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
	 * The Class that describes object oriented classes that exist in the program
	 */
public class RecoveredClass {

	private String name;
	private CategoryPath classPath;
	private Namespace classNamespace;
	private DataTypeManager dataTypeManager;

	private List<Address> vftableAddresses = new ArrayList<Address>();
	private List<Function> allClassVirtualFunctions = new ArrayList<Function>();

	private boolean hasParentClass = false;
	private boolean hasChildClass = false;
	private boolean hasVftable = true;

	private boolean hasSingleInheritance = false;
	private boolean hasMultipleInheritance = false;
	private boolean hasMultipleVirtualInheritance = false;

	private List<Function> constructorAndDestructorList = new ArrayList<Function>();
	private List<Function> constructorList = new ArrayList<Function>();
	private List<Function> inlinedConstructorList = new ArrayList<Function>();
	private List<Function> destructorList = new ArrayList<Function>();
	private List<Function> inlinedDestructorList = new ArrayList<Function>();
	private List<Function> deletingDestructors = new ArrayList<Function>();
	private List<Function> nonThisDestructors = new ArrayList<Function>();
	private List<Function> cloneFunctions = new ArrayList<Function>();
	private List<Function> indeterminateList = new ArrayList<Function>();
	private List<Function> indeterminateInlineList = new ArrayList<Function>();

	private Map<Address, List<Function>> vftableToVfunctionsMap =
		new HashMap<Address, List<Function>>();

	private List<RecoveredClass> classHierarchy = new ArrayList<RecoveredClass>();
	private Map<RecoveredClass, List<RecoveredClass>> classHierarchyMap =
		new HashMap<RecoveredClass, List<RecoveredClass>>();

	private Map<Address, RecoveredClass> vftableToBaseClassMap =
		new HashMap<Address, RecoveredClass>();
	private Map<Integer, Address> orderToVftableMap = new HashMap<Integer, Address>();

	private Map<Integer, Address> classOffsetToVftableMap = new HashMap<Integer, Address>();

	private List<RecoveredClass> parentList = new ArrayList<RecoveredClass>();
	private Map<RecoveredClass, Boolean> parentToBaseTypeMap =
		new HashMap<RecoveredClass, Boolean>();

	private List<RecoveredClass> childClasses = new ArrayList<RecoveredClass>();

	private Address vbtableAddress = null;
	private Structure vbtableStructure = null;
	private int vbtableOffset = NONE;

	private boolean inheritsVirtualAncestor = false;
	private boolean isPublicClass = false;
	private boolean isDiamondShaped = false;

	private Structure existingClassStructure = null;
	private Structure computedClassStructure = null;
	private boolean hasExistingClassStructure = false;
	private Function vbaseDestructor = null;

	private String shortenedTemplateName = new String();

	private static final int NONE = -1;

	TaskMonitor monitor = TaskMonitor.DUMMY;
	EditStructureUtils structUtils;


	RecoveredClass(String name, CategoryPath classPath, Namespace classNamespace,
			DataTypeManager dataTypeManager) {
		this.name = name;
		this.classPath = classPath;
		this.classNamespace = classNamespace;
		this.dataTypeManager = dataTypeManager;

		this.structUtils = new EditStructureUtils();
	}

	public String getName() {
		return name;
	}

	public List<Function> getVirtualFunctions(Address vftableAddress) {
		return vftableToVfunctionsMap.get(vftableAddress);
	}

	public List<Function> getAllVirtualFunctions() {
		return allClassVirtualFunctions;
	}

	public CategoryPath getClassPath() {
		return classPath;
	}

	public Namespace getClassNamespace() {
		return classNamespace;
	}

	public void setHasParentClass(boolean bool) {
		hasParentClass = bool;
		return;
	}

	public boolean hasParentClass() {
		return hasParentClass;
	}

	public void setHasChildClass(boolean bool) {
		hasChildClass = true;
	}

	public boolean hasChildClass() {
		return hasChildClass;
	}

	public void addParent(RecoveredClass recoveredClass) {
		if (!parentList.contains(recoveredClass)) {
			parentList.add(recoveredClass);
		}
	}

	public List<RecoveredClass> getParentList() {
		return parentList;
	}

	public void addVftableAddress(Address address) {
		vftableAddresses.add(address);
		setHasVftable(true);
	}

	public List<Address> getVftableAddresses() {
		return vftableAddresses;
	}

	public void addVftableVfunctionsMapping(Address vftAddress, List<Function> vfunctions) {
		vftableToVfunctionsMap.put(vftAddress, vfunctions);
		allClassVirtualFunctions.addAll(vfunctions);
	}

	public void addVftableToBaseClassMapping(Address vftAddress, RecoveredClass recoveredClass) {
		vftableToBaseClassMap.put(vftAddress, recoveredClass);
	}

	public RecoveredClass getVftableBaseClass(Address address) {
		return vftableToBaseClassMap.get(address);
	}

	public void addOrderToVftableMapping(Integer order, Address address) {
		orderToVftableMap.put(order, address);
	}

	public Map<Integer, Address> getOrderToVftableMap() {
		return orderToVftableMap;
	}

	public void addClassOffsetToVftableMapping(int offset, Address vftableAddress)
			throws Exception {

		// already have this mapping
		if (classOffsetToVftableMap.get(offset) == vftableAddress) {
			return;
		}

		if (!classOffsetToVftableMap.keySet().contains(offset)) {

			// error if try to add same address to different offset
			if (classOffsetToVftableMap.values().contains(vftableAddress)) {
				throw new Exception(name + " trying to add same vftable address " +
					vftableAddress.toString() + " to new offset " + offset);
			}

			classOffsetToVftableMap.put(offset, vftableAddress);
			return;
		}

		// error if try to add different address to same offset
		Address address = classOffsetToVftableMap.get(offset);
		if (!address.equals(vftableAddress)) {
			throw new Exception(name + " trying to add different vftable address (old: " +
				vftableAddress.toString() + " new: " + address.toString() + ")  to same offset " +
				offset);
		}

	}

	public Map<Integer, Address> getClassOffsetToVftableMap() {
		return classOffsetToVftableMap;
	}

	public void addParentToBaseTypeMapping(RecoveredClass recoveredClass, Boolean isVirtualBase) {

		if (!parentToBaseTypeMap.keySet().contains(recoveredClass)) {
			parentToBaseTypeMap.put(recoveredClass, isVirtualBase);
		}
	}

	public Map<RecoveredClass, Boolean> getParentToBaseTypeMap() {
		return parentToBaseTypeMap;
	}

	public void setVbtableAddress(Address address) {
		vbtableAddress = address;
	}

	public Address getVbtableAddress() {
		return vbtableAddress;
	}

	public void setVbtableStructure(Structure structure) {
		vbtableStructure = structure;
	}

	public Structure getVbtableStructure() {
		return vbtableStructure;
	}

	public void setVbtableOffset(int offset) {
		vbtableOffset = offset;
	}

	public int getVbtableOffset() {
		return vbtableOffset;
	}

	public void setInheritsVirtualAncestor(boolean setting) {
		inheritsVirtualAncestor = setting;
	}

	public boolean inheritsVirtualAncestor() {
		return inheritsVirtualAncestor;
	}

	public void setIsPublicClass(boolean setting) {
		isPublicClass = setting;
	}

	public boolean isPublicClass() {
		return isPublicClass;
	}

	public void setIsDiamondShaped(boolean setting) {
		isDiamondShaped = setting;
	}

	public boolean isDiamondShaped() {
		return isDiamondShaped;
	}

	public void setHasVftable(boolean setting) {
		hasVftable = setting;
	}

	public boolean hasVftable() {
		return hasVftable;
	}

	public void setHasSingleInheritance(boolean hasSingleInheritanceSetting) {
		hasSingleInheritance = hasSingleInheritanceSetting;
	}

	public boolean hasSingleInheritance() {
		return hasSingleInheritance;
	}

	public void setHasMultipleInheritance(boolean hasMultipleInheritanceSetting) {
		hasMultipleInheritance = hasMultipleInheritanceSetting;
	}

	public boolean hasMultipleInheritance() {
		return hasMultipleInheritance;
	}

	public void setHasMultipleVirtualInheritance(boolean hasMultVirtSetting) {
		hasMultipleVirtualInheritance = hasMultVirtSetting;
	}

	public boolean hasMultipleVirtualInheritance() {
		return hasMultipleVirtualInheritance;
	}

	public void addConstructorDestructorList(List<Function> list) {
		Iterator<Function> iterator = list.iterator();
		while (iterator.hasNext()) {

			Function function = iterator.next();
			if (!constructorAndDestructorList.contains(function)) {
				constructorAndDestructorList.add(function);
			}
		}
		return;
	}

	public void removeFromConstructorDestructorList(Function function) {
		if (constructorAndDestructorList.contains(function)) {
			constructorAndDestructorList.remove(function);
		}
	}

	public void addConstructor(Function function) {
		if (!constructorList.contains(function)) {
			constructorList.add(function);
		}
		return;
	}

	public void addDestructor(Function function) {
		if (!destructorList.contains(function)) {
			destructorList.add(function);
		}
		return;
	}

	public void addInlinedConstructor(Function function) {
		if (!inlinedConstructorList.contains(function)) {
			inlinedConstructorList.add(function);
		}
		return;
	}

	public void addInlinedDestructor(Function function) {
		if (!inlinedDestructorList.contains(function)) {
			inlinedDestructorList.add(function);
		}
		return;
	}

	public void addNonThisDestructor(Function function) {
		if (!nonThisDestructors.contains(function)) {
			nonThisDestructors.add(function);
		}
	}

	public void addIndeterminateInline(Function function) {
		if (!indeterminateInlineList.contains(function)) {
			indeterminateInlineList.add(function);
		}
		return;
	}

	public void removeIndeterminateInline(Function function) {
		if (indeterminateInlineList.contains(function)) {
			indeterminateInlineList.remove(function);
		}
		return;
	}

	public void addIndeterminateConstructorOrDestructorList(List<Function> list) {
		Iterator<Function> iterator = list.iterator();
		while (iterator.hasNext()) {
			Function function = iterator.next();
			if (!indeterminateList.contains(function)) {
				indeterminateList.add(function);
			}
		}
		return;
	}

	public void removeIndeterminateConstructorOrDestructor(Function function) {
		if (indeterminateList.contains(function)) {
			indeterminateList.remove(function);
		}
		return;
	}

	public List<Function> getConstructorOrDestructorFunctions() {
		return constructorAndDestructorList;
	}

	public List<Function> getConstructorList() {
		return constructorList;
	}

	public List<Function> getInlinedConstructorList() {
		return inlinedConstructorList;
	}

	public List<Function> getDestructorList() {
		return destructorList;
	}

	public List<Function> getInlinedDestructorList() {
		return inlinedDestructorList;
	}

	public List<Function> getNonThisDestructors() {
		return nonThisDestructors;
	}

	public List<Function> getIndeterminateList() {
		return indeterminateList;
	}

	public List<Function> getIndeterminateInlineList() {
		return indeterminateInlineList;
	}

	public void addChildClass(RecoveredClass recoveredClass) {
		if (!childClasses.contains(recoveredClass)) {
			childClasses.add(recoveredClass);
		}
		return;
	}

	public List<RecoveredClass> getChildClasses() {
		return childClasses;
	}

	public void addExistingClassStructure(Structure classStructure) {
		if (classStructure == null) {
			return;
		}
		existingClassStructure = classStructure;
		hasExistingClassStructure = true;
		return;
	}

	public Structure getExistingClassStructure() {
		return existingClassStructure;
	}

	public boolean hasExistingClassStructure() {
		return hasExistingClassStructure;
	}

	public void updateClassMemberStructure(Structure structure) throws CancelledException {

		// initialize by copying first structure
		if (computedClassStructure == null) {

			computedClassStructure =
				new StructureDataType(classPath, name, structure.getLength(), dataTypeManager);

			int numComponents = structure.getNumComponents();
			for (int i = 0; i < numComponents; i++) {
				DataTypeComponent component = structure.getComponent(i);
				int offset = component.getOffset();

				computedClassStructure.replaceAtOffset(offset, component.getDataType(),
					component.getDataType().getLength(), component.getFieldName(),
					component.getComment());
			}

			return;
		}

		// update initial structure using all further structures
		if (structure.getLength() > computedClassStructure.getLength()) {
			computedClassStructure.growStructure(
				structure.getLength() - computedClassStructure.getLength());
		}

		DataTypeComponent[] definedComponents = structure.getDefinedComponents();
		for (DataTypeComponent newComponent : definedComponents) {

			DataType newComponentDataType = newComponent.getDataType();

			int offset = newComponent.getOffset();

			DataTypeComponent currentComponent =
				computedClassStructure.getComponentContaining(offset);
			DataType currentComponentDataType = currentComponent.getDataType();

			if (currentComponentDataType.equals(newComponentDataType)) {
				continue;
			}

			int length = newComponentDataType.getLength();
			String fieldName = newComponent.getFieldName();
			String comment = newComponent.getComment();

			// if it is any empty placeholder structure - replace with 
			// undefined1 dt
			if (newComponentDataType instanceof Structure &&
				newComponentDataType.isNotYetDefined()) {

				computedClassStructure.replaceAtOffset(offset, new Undefined1DataType(), 1,
					fieldName, comment);
				continue;
			}

			// replace pointers to existing class data type with void pointer of same size
			if (newComponentDataType instanceof Pointer &&
				newComponentDataType.getName().equals(name + " *")) {

				DataType voidDT = new VoidDataType();

				Pointer pointer = new PointerDataType();
				if (newComponentDataType.getLength() == 4) {
					pointer = new Pointer32DataType(voidDT);
				}
				if (newComponentDataType.getLength() == 8) {
					pointer = new Pointer64DataType(voidDT);
				}
				computedClassStructure.replaceAtOffset(offset, pointer, pointer.getLength(),
					fieldName, comment);
				continue;
			}

			// if the new component is a non-empty structure, check to see if the current
			// structure has undefined or equivalent components and replace with new struct if so
			if (newComponentDataType instanceof Structure) {
				if (structUtils.hasReplaceableComponentsAtOffset(computedClassStructure,
					offset, (Structure) newComponentDataType, monitor)) {

					boolean successfulClear =
						structUtils.clearLengthAtOffset(computedClassStructure, offset,
							length, monitor);

					if (successfulClear) {
						computedClassStructure.replaceAtOffset(offset, newComponentDataType, length,
							fieldName, comment);
					}
					continue;
				}
			}

			// if current component is undefined size 1 and new component is not undefined size 1
			// then replace it
			if (structUtils.isUndefined1(currentComponentDataType) &&
				!structUtils.isUndefined1(newComponentDataType)) {
				if (structUtils.hasEnoughUndefinedsOfAnyLengthAtOffset(computedClassStructure,
					offset, length, monitor)) {
					boolean successfulClear =
						structUtils.clearLengthAtOffset(computedClassStructure, offset,
							length, monitor);

					if (successfulClear) {
						computedClassStructure.replaceAtOffset(offset, newComponentDataType, length,
							fieldName, comment);
					}
				}
				continue;
			}

			// if new component is not an undefined data type and the current componenent(s)
			// that make up new component length are all undefineds then clear and replace
			// the current component(s) with the new one
			if (structUtils.isUndefined(currentComponentDataType) &&
				!structUtils.isUndefined(newComponentDataType)) {

				if (structUtils.hasEnoughUndefinedsOfAnyLengthAtOffset(computedClassStructure,
					offset, length, monitor)) {
					boolean successfulClear =
						structUtils.clearLengthAtOffset(computedClassStructure, offset,
							length, monitor);

					if (successfulClear) {
						computedClassStructure.replaceAtOffset(offset, newComponentDataType, length,
							fieldName, comment);
					}
				}
			}
		}

		return;
	}

	// TODO: remove once FillOutStructCmd updates to put Undefined1 instead of undefined
	// for saved offsets
	public void updateClassMemberStructureUndefineds(NoisyStructureBuilder componentMap) {

		Iterator<Entry<Long, DataType>> componentMapIterator = componentMap.iterator();
		while (componentMapIterator.hasNext()) {
			Entry<Long, DataType> next = componentMapIterator.next();
			Long offset = next.getKey();
			DataType dataType = next.getValue();

			if (computedClassStructure.getLength() < (offset.intValue() + dataType.getLength())) {
				continue;
			}

			if (structUtils.isUndefined1(dataType)) {
				dataType = new Undefined1DataType();
				DataTypeComponent component =
					computedClassStructure.getComponentAt(offset.intValue());

				if (!component.getDataType().equals(dataType)) {
					computedClassStructure.replaceAtOffset(offset.intValue(), dataType,
						dataType.getLength(), component.getFieldName(), component.getComment());
				}
			}
		}
	}

	public Structure getComputedClassStructure() {
		return computedClassStructure;
	}

	public void addCloneFunction(Function function) {
		if (!cloneFunctions.contains(function)) {
			cloneFunctions.add(function);
		}
	}

	public List<Function> getCloneFunctions() {
		return cloneFunctions;
	}

	public void addDeletingDestructor(Function function) {
		if (!deletingDestructors.contains(function)) {
			deletingDestructors.add(function);
		}
	}

	public List<Function> getDeletingDestructors() {
		return deletingDestructors;
	}

	public void setVBaseDestructor(Function function) {
		vbaseDestructor = function;
	}

	public Function getVBaseDestructor() {
		return vbaseDestructor;
	}

	public void setClassHierarchy(List<RecoveredClass> list) {
		classHierarchy.addAll(list);
		return;
	}

	public List<RecoveredClass> getClassHierarchy() {
		return classHierarchy;
	}

	public void addClassHierarchyMapping(RecoveredClass recoveredClass,
			List<RecoveredClass> recoveredClasses) {

		if (!classHierarchyMap.keySet().contains(recoveredClass)) {
			classHierarchyMap.put(recoveredClass, recoveredClasses);
		}
	}

	public Map<RecoveredClass, List<RecoveredClass>> getClassHierarchyMap() {
		return classHierarchyMap;
	}

	public void addShortenedTemplatedName(String shortenedName) {
		shortenedTemplateName = shortenedName;
	}

	public String getShortenedTemplateName() {
		return shortenedTemplateName;
	}
}

