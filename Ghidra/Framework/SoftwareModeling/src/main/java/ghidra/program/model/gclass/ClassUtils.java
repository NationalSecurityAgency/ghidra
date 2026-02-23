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

import ghidra.app.util.SymbolPath;
import ghidra.program.model.data.*;

/**
 * Utility class for Class-related software modeling.
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

}
