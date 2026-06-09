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
package ghidra.program.model.gclass;

import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.util.SymbolPath;
import ghidra.program.model.data.*;

/**
 * Utility class for Class-related software modeling.
 * <p>
 * This class is experimental and subject to unannounced changes, including changes to processing
 * philosophies and removal of methods
 */
public class ClassUtils {

	// Prototype values for now.  Need to come to agreement on what these should be.  Might want
	//  a separate one for a generic virtual table (not "base" or "function") for gcc/Itanium
	//  standard
	/**
	 * Standard field name for a class virtual table
	 */
	public static final String VTABLE = "vtable";

	/**
	 * Standard field name for a class virtual base table
	 */
	public static final String VBTABLE = "vbtable";

	/**
	 * Standard field name for a class virtual function table
	 */
	public static final String VFTABLE = "vftable";

	/**
	 * Standard field name for a virtual table pointer found within a class
	 */
	public static final String VTPTR = "vtptr";

	/**
	 * Standard field name for a virtual base table pointer found within a class
	 */
	public static final String VBPTR = "vbptr";

	/**
	 * Standard field name for a virtual function table pointer found within a class
	 */
	public static final String VFPTR = "vfptr";

	/**
	 * Type used for {@link #VBPTR} and {@link #VFPTR} fields in a class
	 */
	public static final PointerDataType VXPTR_TYPE = new PointerDataType();

	/**
	 * The standard prefix/suffix used for vxtable offset tag in its description.  Private for now.
	 */
	private static final String VXTABLE_DESCRIPTION_PREFIX = "{{vtoffset 0x";
	private static final String VXTABLE_DESCRIPTION_SUFFIX = "}}";
	private static final int VXTABLE_DESCRIPTION_PREFIX_LEN = VXTABLE_DESCRIPTION_PREFIX.length();

	/**
	 * private constructor -- no instances
	 */
	private ClassUtils() {
		// no instances
	}

	/**
	 * Returns the category path for class internals
	 * @param composite the class composite
	 * @return the category path
	 */
	public static CategoryPath getClassInternalsPath(Composite composite) {
		DataTypePath dtp = composite.getDataTypePath();
		return getClassInternalsPath(dtp.getCategoryPath(), dtp.getDataTypeName());
	}

	/**
	 * Returns the category path for items belonging to this class, such as vxtables
	 * @param composite the class composite
	 * @return the category path
	 */
	public static CategoryPath getClassPath(Composite composite) {
		DataTypePath dtp = composite.getDataTypePath();
		return new CategoryPath(dtp.getCategoryPath(), dtp.getDataTypeName());
	}

	/**
	 * Returns the category path for class for the ClassID
	 * @param id the class ID
	 * @return the category path
	 */
	public static CategoryPath getClassPath(ClassID id) {
		return recurseGetCategoryPath(id.getCategoryPath(), id.getSymbolPath());
	}

	/**
	 * Returns the category path for class internals for the Class CategoryPath
	 * @param category the class category path
	 * @return the category path
	 */
	public static CategoryPath getClassInternalsPath(CategoryPath category) {
		return category.extend("!internal");
	}

	/**
	 * Returns the category path for class internals for the ClassID
	 * @param id the class ID
	 * @return the category path
	 */
	public static CategoryPath getClassInternalsPath(ClassID id) {
		return getClassInternalsPath(getClassPath(id));
	}

	/**
	 * Returns the category path for class internals
	 * @param path the category path of the class composite
	 * @param className the name of the class
	 * @return the category path
	 */
	public static CategoryPath getClassInternalsPath(CategoryPath path, String className) {
		return new CategoryPath(new CategoryPath(path, className), "!internal");
	}

	/**
	 * Returns the data type path for a suitable base class
	 * @param composite the class composite
	 * @return the base class data type path
	 */
	public static DataTypePath getBaseClassDataTypePath(Composite composite) {
		return new DataTypePath(getClassInternalsPath(composite), composite.getName());
	}

	/**
	 * Returns the "self-base" composite for the specified class composite.  This could be
	 * the composite argument itself of could be a component of it
	 * @param composite the main class type
	 * @return the self-base composite
	 */
	public static Composite getSelfBaseType(Composite composite) {
		DataTypeManager dtm = composite.getDataTypeManager();
		DataTypePath dtp = getBaseClassDataTypePath(composite);
		DataType dt = dtm.getDataType(dtp);
		if (dt instanceof Composite base) {
			return base;
		}
		if (composite.getNumComponents() > 0) {
			DataTypeComponent component = composite.getComponent(0);
			DataType componentType = component.getDataType();
			if (componentType instanceof Structure struct) {
				if (struct.getDataTypePath().equals(dtp)) {
					return struct;
				}
			}
		}
		return composite;
	}

	/**
	 * Returns the "self-base" composite for the specified class ID
	 * @param dtm the data type manager
	 * @param id the class id
	 * @return the self-base composite
	 */
	public static Composite getSelfBaseType(DataTypeManager dtm, ClassID id) {
		CategoryPath mainCp = getClassPath(id);
		CategoryPath baseCp = getClassInternalsPath(mainCp);
		String name = id.getSymbolPath().getName();
		DataTypePath dtp = new DataTypePath(baseCp, name);
		DataType dt = dtm.getDataType(dtp);
		if (dt instanceof Composite composite) {
			return composite;
		}
		if (dt != null) {
			return null;
		}
		// If we make change to put class A::B into Category /A/B instead of just in /B,
		//  we will need to change from getParent() to something else here; or make a
		//  change elsewhere
		dtp = new DataTypePath(mainCp.getParent(), name);
		dt = dtm.getDataType(dtp);
		if (dt instanceof Composite composite) {
			return composite;
		}
		return null;
	}

	/**
	 * Indicates whether a label satisfies the format of a vxtable label
	 * @param type the data type
	 * @return {@code true} if is a vxtable label format
	 */
	public static boolean isVTable(DataType type) {
		if (!(type instanceof Structure struct)) {
			return false;
		}
		String description = struct.getDescription();
		if (validateVtableDescriptionOffsetTag(description) == null) {
			return false;
		}
		return true;
	}

	/**
	 * Provides the __TEMPORARY__ standard special Description string for a virtual table (e.g.,
	 * vtable, vbtable, vftable) that is keyed off of by the Decompiler during flattening and
	 * replacement of types within a class structure.  This is __TEMPORARY__ in that we hope
	 * to use some special attribute in the future.  More details to come
	 * @param ptrOffsetInClass the offset of the special field within the class
	 * @return the special name
	 */
	public static String createVxTableDescriptionOffsetTag(long ptrOffsetInClass) {
		return String.format("%s%08x%s", VXTABLE_DESCRIPTION_PREFIX, ptrOffsetInClass,
			VXTABLE_DESCRIPTION_SUFFIX);
	}

	/**
	 * Validates a Vtable description and returns the encoded offset value
	 * @param description the description string
	 * @return the offset or {@code null} if invalid name
	 */
	public static Long validateVtableDescriptionOffsetTag(String description) {
		if (description == null) {
			return null;
		}
		int start = description.indexOf(VXTABLE_DESCRIPTION_PREFIX);
		if (start == -1) {
			return null;
		}
		start += VXTABLE_DESCRIPTION_PREFIX_LEN;
		int end =
			description.indexOf(VXTABLE_DESCRIPTION_SUFFIX, start);
		if (end == -1) {
			return null;
		}
		String sub = description.substring(start, end);
		try {
			return Long.parseLong(sub, 16);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	/**
	 * Returns a default data type for a VFT
	 * @param dtm the data type manager
	 * @return the pointer data type
	 */
	public static PointerDataType getVftDefaultEntry(DataTypeManager dtm) {
		return new PointerDataType(dtm);
	}

	/**
	 * Returns a default data type for a VBT
	 * @param dtm the data type manager
	 * @return the data type
	 */
	public static DataType getVbtDefaultEntry(DataTypeManager dtm) {
		return new IntegerDataType(dtm);
	}

	/**
	 * Returns the size of the default pointer data type for a VFT entry
	 * @param dtm the data type manager
	 * @return the size
	 */
	public static int getVftEntrySize(DataTypeManager dtm) {
		return dtm.getDataOrganization().getPointerSize();
	}

	/**
	 * Returns the size of the default data type for a VBT entry
	 * @param dtm the data type manager
	 * @return the size
	 */
	public static int getVbtEntrySize(DataTypeManager dtm) {
		return dtm.getDataOrganization().getIntegerSize();
	}

	/**
	 * Method to get a category path from a base category path and symbol path
	 * @param category the {@ink CategoryPath} on which to build
	 * @param symbolPath the current {@link SymbolPath} from which the current name is pulled.
	 * @return the new {@link CategoryPath} for the recursion level
	 */
	private static CategoryPath recurseGetCategoryPath(CategoryPath category,
			SymbolPath symbolPath) {
		SymbolPath parent = symbolPath.getParent();
		if (parent != null) {
			category = recurseGetCategoryPath(category, parent);
		}
		return new CategoryPath(category, symbolPath.getName());
	}

	/**
	 * Finds and returns list of replacement pointer types for the specified owner class structure
	 * @param dtm the data type manager
	 * @param type the class structure type
	 * @return the map of offset to owner replacement types
	 */
	public static Map<Long, Pointer> getReplacementPointers(DataTypeManager dtm,
			Structure type) {
		CategoryPath path = getClassPath(type);
		Map<Long, Pointer> results = new HashMap<>();
		Category category = dtm.getCategory(path);
		if (category == null) {
			return results;
		}
		for (DataType dt : category.getDataTypes()) {
			if (!(dt instanceof Structure struct)) {
				continue;
			}
			Long offset =
				ClassUtils.validateVtableDescriptionOffsetTag(struct.getDescription());
			if (offset == null) {
				continue;
			}
			Pointer vxtptr = new PointerDataType(struct);
			results.put(offset, vxtptr);
		}
		return results;
	}

	/**
	 * Record containing a name and a pointer data type
	 * @param name the name
	 * @param pointer the pointer type
	 */
	public static record NameAndPointer(String name, DataType pointer) {}

	/**
	 * Tries to provide an appropriate data type replacement for special components, particularly
	 *  for class objects such as virtual function table and virtual base table pointers within
	 *  a flattened class structure
	 * @param component the component to be checked
	 * @param accumulatedOffset the accumulated offset of the component due to flattening
	 * @param ownerVxtptrs the map of offset to owner vxtptr types
	 * @return the replacement data type or the original type if there is no replacement needed
	 */
	public static NameAndPointer getReplacementType(DataTypeComponent component,
			long accumulatedOffset, Map<Long, Pointer> ownerVxtptrs) {
		if (!hasReplaceAttribute(component)) {
			return null;
		}
		String fieldName = component.getFieldName();
		Pointer vxtptr = ownerVxtptrs.get(accumulatedOffset);
		if (vxtptr == null) {
			return null;
		}
		DataType dt = vxtptr.getDataType();
		String dtName = dt.getName(); // We are not using the full path name
		String newFieldName;
		if (dtName.startsWith(ClassUtils.VTABLE)) {
			if (!ClassUtils.VTPTR.equals(fieldName)) {
				return null;
			}
			newFieldName = fieldName + dtName.substring(VTABLE.length()); //crash if not more char
		}
		else if (dtName.startsWith(ClassUtils.VBTABLE)) {
			if (!ClassUtils.VBPTR.equals(fieldName)) {
				return null;
			}
			newFieldName = fieldName + dtName.substring(VFTABLE.length()); //crash if not more char
		}
		else if (dtName.startsWith(ClassUtils.VFTABLE)) {
			if (!ClassUtils.VFPTR.equals(fieldName)) {
				return null;
			}
			newFieldName = fieldName + dtName.substring(VBTABLE.length()); //crash if not more char
		}
		else {
			return null;
		}
		return new NameAndPointer(newFieldName, vxtptr);
	}

	/**
	 * Tries to provide an appropriate data type replacement for special components, particularly
	 *  for class objects such as virtual function table and virtual base table pointers within
	 *  a flattened class structure.  The {@code structure} argument becomes the return type if
	 *  {@code enabled} is {@code false}, if the argument structure does not have class
	 *  attributes, or if there is no suitable replacement for it
	 * @param structure the structure to process
	 * @param enabled {@code false} will immediately return the argument type
	 * @return the replacement data type or null if could not or did not need to be replaced
	 */
	public static Structure getReplacementType(Structure structure, boolean enabled) {
		if (!enabled) {
			return structure;
		}
		if (!hasClassAttribute(structure)) {
			return structure;
		}
		Structure replacement = getReplacementType(structure);
		return replacement == null ? structure : replacement;
	}

	/**
	 * Tries to provide an appropriate data type replacement for special components, particularly
	 *  for class objects such as virtual function table and virtual base table pointers within
	 *  a flattened class structure
	 * @param structure the structure to process
	 * @return the replacement data type or null if could not or did not need to be replaced
	 */
	public static Structure getReplacementType(Structure structure) {
		DataTypeManager dtm = structure.getDataTypeManager();
		Map<Long, Pointer> vxtptrs = ClassUtils.getReplacementPointers(dtm, structure);
		StructureDataType newStruct = new StructureDataType(structure.getCategoryPath(),
			structure.getName(), 0, structure.getDataTypeManager());
		newStruct.setPackingEnabled(false);
		// Future: consider whether we need to strip the class attribute from the description
		//  of the resultant type.  Decompiler might still want/need it; but we probably don't
		//  want it if it allows us to do replacement again (unless it doesn't really do
		//  anything on another pass of replacement). This comment is really for while we are
		//  using the description field to hold an attribute; this comment can be deleted once
		//  we are not using the field for holding an attribute.
		newStruct.setDescription(structure.getDescription());
		try {
			if (processComponents(structure, newStruct, 0, vxtptrs)) {
				newStruct.setLength(structure.getLength());
				// The original structure should be packed, so we can use its alignment
				// as the alignment of our flattened structure.  We do not want to turn on
				// packing for the flattened structure unless we supply appropriate padding
				newStruct.align(structure.getAlignment());
				return newStruct;
			}
		}
		catch (InvalidDataTypeException e) {
			// squelch
		}
		return null;
	}

	/**
	 * Tries to provide an appropriate data type replacement for special components, particularly
	 *  for class objects such as virtual function table and virtual base table pointers within
	 *  a flattened class structure
	 * @param type the structure to process
	 * @param newType the new structure being created
	 * @param baseOffset the accumulated offset of the component due to flattening
	 * @param ownerVxtptrs the map of offset to owner vxtptr types
	 * @return {@code true} if successful
	 * @throws InvalidDataTypeException upon error
	 */
	private static boolean processComponents(Structure type, StructureDataType newType,
			int baseOffset, Map<Long, Pointer> ownerVxtptrs) throws InvalidDataTypeException {
		DataTypeComponent[] comps = type.getDefinedComponents();
		boolean mod = false;
		for (DataTypeComponent comp : comps) {
			int accumulatedOffset = baseOffset + comp.getOffset();
			if ((comp.getDataType() instanceof Structure struct && hasFlattenAttribute(comp))) {
				processComponents(struct, newType, accumulatedOffset, ownerVxtptrs);
				mod = true;
				continue;
			}
			if (comp.getLength() == 0) {
				continue;
			}
			if (comp instanceof BitFieldDataType bfComp) {
				DataTypeComponent bfdtc = newType.insertBitFieldAt(accumulatedOffset,
					bfComp.getBaseTypeSize(), bfComp.getBitOffset(), comp.getDataType(),
					bfComp.getBitSize(), comp.getFieldName(), comp.getComment());
				if (bfdtc.getOffset() != accumulatedOffset) {
					throw new InvalidDataTypeException();
				}
				continue;
			}
			ClassUtils.NameAndPointer nap =
				ClassUtils.getReplacementType(comp, accumulatedOffset, ownerVxtptrs);
			String fieldName;
			DataType fieldType;
			if (nap == null) {
				fieldName = comp.getFieldName();
				fieldType = comp.getDataType();
			}
			else {
				fieldName = nap.name();
				fieldType = nap.pointer();
				mod = true;
			}
			if (fieldName == null || fieldName.length() == 0) {
				fieldName = comp.getDefaultFieldName();
			}
			DataTypeComponent dtc =
				newType.insertAtOffset(accumulatedOffset, fieldType, fieldType.getLength(),
					fieldName, comp.getComment());
			if (dtc.getOffset() != accumulatedOffset) {
				throw new InvalidDataTypeException();
			}
		}
		return mod;
	}

	/**
	 * This method returns true if the argument structure has a class attribute
	 * @param structure the structure under question
	 * @return {@code true} if has a class attribute
	 */
	public static boolean hasClassAttribute(Structure structure) {
		// Future: Check attribute on structure
		String description = structure.getDescription();
		if (StringUtils.isEmpty(description)) {
			return false;
		}
		return true; // true for now... later do the next line
		//return description.contains("{{class}}");
	}

	/**
	 * We hope to have the ability to set and use a "flatten" attribute on the component of
	 * the structure
	 * <p> This method is temporary for investigations... should rely on a real component attribute
	 * @param component the member to check
	 * @return {@code true} if has flatten attribute
	 */
	private static boolean hasFlattenAttribute(DataTypeComponent component) {
		// Future: Check ComponentMutationEnum/Mode
		String comment = component.getComment();
		if (comment == null) {
			return false;
		}
		if (comment.startsWith("Base") || comment.startsWith("Self Base") ||
			comment.startsWith("Virtual Base")) {
			return true;
		}
		return comment.contains("{{flatten}}");
	}

	/**
	 * We hope to have the ability to set and use a "replace" attribute on the component of
	 * the structure
	 * <p> This method is temporary for investigations... should rely on a real component attribute
	 * @param component the member to check
	 * @return {@code true} if has replace attribute
	 */
	private static boolean hasReplaceAttribute(DataTypeComponent component) {
		// Future: Check ComponentMutationEnum/Mode
		DataType fieldType = component.getDataType();
		if (!(fieldType instanceof Pointer ptr) || ptr.getDataType() != null) {
			return false;
		}
		String fieldName = component.getFieldName();
		if (ClassUtils.VFPTR.equals(fieldName) || ClassUtils.VBPTR.equals(fieldName)) {
			return true;
		}
		String comment = component.getComment();
		if (comment == null) {
			return false;
		}
		return comment.contains("{{replace}}");
	}

}
