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

import ghidra.program.model.data.*;

/**
 * Utility class for Class-related software modeling.
 */
public class ClassUtils {

	// Prototype values for now.  Need to come to agreement on what these should be.  Might want
	//  a separate one for a generic virtual table (not "base" or "function") for gcc/Itanium
	//  standard
	/**
	 * Standard field name for a virtual base table pointer found within a class
	 */
	public static final String VBPTR = "{vbptr}";

	/**
	 * Standard field name for a virtual function table pointer found within a class
	 */
	public static final String VFPTR = "{vfptr}";

	/**
	 * Type used for {@link #VBPTR} and {@link #VFPTR} fields in a class
	 */
	public static final PointerDataType VXPTR_TYPE = new PointerDataType();

	/**
	 * private constructor -- no instances
	 */
	private ClassUtils() {
		// no instances
	}

	/**
	 * Returns the category for class internals
	 * @param composite the class composite
	 * @return the category path
	 */
	public static CategoryPath getClassInternalsPath(Composite composite) {
		DataTypePath dtp = composite.getDataTypePath();
		return new CategoryPath(new CategoryPath(dtp.getCategoryPath(), dtp.getDataTypeName()),
			"!internal");
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
		DataTypePath dtp = ClassUtils.getBaseClassDataTypePath(composite);
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

}
