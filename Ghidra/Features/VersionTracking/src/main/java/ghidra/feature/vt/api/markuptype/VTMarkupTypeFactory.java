/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.feature.vt.api.markuptype;

import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

import java.util.*;

public class VTMarkupTypeFactory {
	private static Map<Integer, VTMarkupType> idToTypeMap = new HashMap<Integer, VTMarkupType>();
	private static Map<VTMarkupType, Integer> typeToIdMap = new HashMap<VTMarkupType, Integer>();

	static {
		// WARNING - never change the id for a markup type. It is the number stored in the database.

//		register(11, DataReferenceMarkupType.INSTANCE);
		register(12, EolCommentMarkupType.INSTANCE);
		register(13, FunctionNameMarkupType.INSTANCE);
//		register(14, FunctionReturnTypeMarkupType.INSTANCE);
//		register(15, FunctionParameterNameMarkupType.INSTANCE);
//		register(16, FunctionParameterDataTypeMarkupType.INSTANCE);
//		register(17, FunctionParameterCommentMarkupType.INSTANCE);
//		register(18, FunctionLocalVariableNameMarkupMigrator.INSTANCE);
//		register(19, FunctionLocalVariableDataTypeMarkupMigrator.INSTANCE);
//		register(20, FunctionLocalVariableCommentMarkupMigrator.INSTANCE);
		register(22, LabelMarkupType.INSTANCE);
		register(23, PlateCommentMarkupType.INSTANCE);
		register(24, PostCommentMarkupType.INSTANCE);
		register(25, PreCommentMarkupType.INSTANCE);
		register(26, RepeatableCommentMarkupType.INSTANCE);
		register(27, DataTypeMarkupType.INSTANCE);
//		register(28, ParametersSignatureMarkupType.INSTANCE);
		register(29, FunctionSignatureMarkupType.INSTANCE);
//		register(30, ParameterNamesMarkupType.INSTANCE);
//		register(31, FunctionInlineMarkupType.INSTANCE);
//		register(32, FunctionNoReturnMarkupType.INSTANCE);
	}

	private static void register(Integer id, VTMarkupType markupType) {
		idToTypeMap.put(id, markupType);
		typeToIdMap.put(markupType, id);
	}

	public static List<VTMarkupType> getMarkupTypes() {
		return new ArrayList<VTMarkupType>(idToTypeMap.values());
	}

	public static VTMarkupType getMarkupType(int id) {
		return idToTypeMap.get(id);
	}

	public static int getID(VTMarkupType markupType) {
		Integer id = typeToIdMap.get(markupType);
		if (id == null) {
			if (SystemUtilities.isInTestingMode()) {
				register(9999, markupType);
				return 9999;
			}
			throw new AssertException("Attempted to use an unregistered VTMarkupType");
		}
		return id;
	}

}
