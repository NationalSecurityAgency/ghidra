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

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.data.*;

/**
 * Utilities in various places regarding ClassTypes
 */
public class ClassTypeUtils {

	private static final String INTERNALS = "!internals";

	private ClassTypeUtils() {
	}

	/**
	 * Returns an "internals" CategoryPath within the datatype managed by the applier
	 * @param applier for the owning composite datatype of the internals path
	 * @return the CategoryPath
	 */
	public static CategoryPath getInternalsCategoryPath(CompositeTypeApplier applier) {
		DataType dt = applier.getDataType();
		if (dt instanceof Composite composite) {
			return getInternalsCategoryPath(composite);
		}
		return null;
	}

	// TODO: Eventually consider changing Composite argument below as model is refined.
	/**
	 * Returns an "internals" CategoryPath for the owning composite datatype
	 * @param composite owning datatype of the internals path
	 * @return the CategoryPath
	 */
	public static CategoryPath getInternalsCategoryPath(Composite composite) {
		DataTypePath dtp = composite.getDataTypePath();
		return dtp.getCategoryPath().extend(dtp.getDataTypeName(), INTERNALS);
	}

	/**
	 * Returns a DataTypePath for the named type within the "internals" category of the type
	 * managed byte the applier
	 * @param applier the applier
	 * @param name the name of the type for the DataTypePath
	 * @return the DataTypePath
	 */
	public static DataTypePath getInternalsDataTypePath(CompositeTypeApplier applier, String name) {
		CategoryPath cp = getInternalsCategoryPath(applier);
		if (cp == null || StringUtils.isAllBlank(name)) {
			return null;
		}
		return new DataTypePath(cp, name);
	}

	// TODO: Eventually consider changing Composite argument below as model is refined.
	/**
	 * Returns a DataTypePath for the named type within the "internals" category of the composite
	 * type
	 * @param composite the composite
	 * @param name the name of the type for the DataTypePath
	 * @return the DataTypePath
	 */
	public static DataTypePath getInternalsDataTypePath(Composite composite, String name) {
		CategoryPath cp = getInternalsCategoryPath(composite);
		if (cp == null || StringUtils.isAllBlank(name)) {
			return null;
		}
		return new DataTypePath(cp, name);
	}
}
