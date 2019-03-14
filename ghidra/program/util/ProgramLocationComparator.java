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
package ghidra.program.util;

import java.util.HashMap;
import java.util.Map;

public class ProgramLocationComparator {
	private static final Class<?>[] PROGRAM_LOCATION_CLASSES = {

	DividerLocation.class, ProgramLocation.class, PlateFieldLocation.class, FunctionLocation.class,
		FunctionRepeatableCommentFieldLocation.class, FunctionSignatureFieldLocation.class,
		FunctionSignatureSourceFieldLocation.class, FunctionCallFixupFieldLocation.class,
		FunctionReturnTypeFieldLocation.class, FunctionCallingConventionFieldLocation.class,
		FunctionNameFieldLocation.class, FunctionStartParametersFieldLocation.class,
		FunctionParameterFieldLocation.class, FunctionParameterNameFieldLocation.class,
		FunctionEndParametersFieldLocation.class, VariableLocation.class,
		VariableTypeFieldLocation.class, VariableNameFieldLocation.class,
		VariableLocFieldLocation.class, VariableXRefFieldLocation.class,
		VariableCommentFieldLocation.class,

		CommentFieldLocation.class, CodeUnitLocation.class, RegisterTransitionFieldLocation.class,
		LabelFieldLocation.class, XRefHeaderFieldLocation.class, XRefFieldLocation.class,
		IndentFieldLocation.class, AddressFieldLocation.class, BytesFieldLocation.class,
		MnemonicFieldLocation.class, OperandFieldLocation.class, FieldNameFieldLocation.class,

		AutomaticCommentFieldLocation.class, RefRepeatCommentFieldLocation.class,
		EolCommentFieldLocation.class, RepeatableCommentFieldLocation.class,
		PostCommentFieldLocation.class,

		SpaceFieldLocation.class, SpacerFieldLocation.class, SubDataFieldLocation.class,
		RegisterFieldLocation.class, };
	public static final ProgramLocationComparator instance = new ProgramLocationComparator();
	private Map<Class<?>, Integer> priorityMap;

	private ProgramLocationComparator() {
		priorityMap = new HashMap<Class<?>, Integer>();
		for (int ordinal = 0; ordinal < PROGRAM_LOCATION_CLASSES.length; ordinal++) {
			priorityMap.put(PROGRAM_LOCATION_CLASSES[ordinal], ordinal);
		}
	}

	public int compare(ProgramLocation loc1, ProgramLocation loc2) {
		int result = loc1.getAddress().compareTo(loc2.getAddress());
		if (result == 0) {
			Class<?> class1 = loc1.getClass();
			Class<?> class2 = loc2.getClass();
			if (class1 == class2) {
				return 0;
			}
			Integer ordinal1 = priorityMap.get(class1);
			Integer ordinal2 = priorityMap.get(class2);
			if (ordinal1 == null && ordinal2 == null) {
				return class1.getName().compareTo(class2.getName());
			}
			if (ordinal1 == null) {
				return 1;
			}
			if (ordinal2 == null) {
				return -1;
			}
			result = ordinal1.intValue() - ordinal2.intValue();
		}
		return result;
	}

}
