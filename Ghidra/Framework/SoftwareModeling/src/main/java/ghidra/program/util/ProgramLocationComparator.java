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

import java.util.*;

import ghidra.program.model.listing.Program;

/**
 * A comparator for the common fields of {@link ProgramLocation}
 * 
 * <p>
 * This comparator only compares the program, address, and class of the program location. To compare
 * at greater granularity, invoke the {@link ProgramLocation#compareTo(ProgramLocation)} method, or
 * use the natural ordering. Each particular type of location uses this comparator, and then
 * compares the more detailed fields, if necessary. If this comparator indicates equality, then the
 * two locations are definitely of the same class.
 */
public class ProgramLocationComparator implements Comparator<ProgramLocation> {
	private static final Class<?>[] PROGRAM_LOCATION_CLASSES = {

		DividerLocation.class, ProgramLocation.class, PlateFieldLocation.class,
		FunctionLocation.class, FunctionRepeatableCommentFieldLocation.class,
		FunctionSignatureFieldLocation.class, FunctionSignatureSourceFieldLocation.class,
		FunctionCallFixupFieldLocation.class, FunctionReturnTypeFieldLocation.class,
		FunctionCallingConventionFieldLocation.class, FunctionNameFieldLocation.class,
		FunctionStartParametersFieldLocation.class, FunctionParameterFieldLocation.class,
		FunctionParameterNameFieldLocation.class, FunctionEndParametersFieldLocation.class,
		VariableLocation.class, VariableTypeFieldLocation.class, VariableNameFieldLocation.class,
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
		RegisterFieldLocation.class,

	};
	// Note, because this calls the constructor, which in turn refers to PROGRAM_LOCATION_CLASSES
	// This must be declared/initialized after PROGRAM_LOCATION_CLASSES
	/** The singleton instance */
	public static final ProgramLocationComparator INSTANCE = new ProgramLocationComparator();

	private Map<Class<?>, Integer> priorityMap;

	private ProgramLocationComparator() {
		priorityMap = new HashMap<>();
		for (int ordinal = 0; ordinal < PROGRAM_LOCATION_CLASSES.length; ordinal++) {
			priorityMap.put(PROGRAM_LOCATION_CLASSES[ordinal], ordinal);
		}
	}

	@Override
	public int compare(ProgramLocation loc1, ProgramLocation loc2) {
		int result;
		// Try to make a sensible comparison of programs before just using identity hashes
		Program program1 = loc1.getProgram();
		Program program2 = loc2.getProgram();
		result = program1.getName().compareTo(program2.getName());
		if (result != 0) {
			return result;
		}
		result = Integer.compare(program1.hashCode(), program2.hashCode());
		if (result != 0) {
			return result;
		}
		result = loc1.getAddress().compareTo(loc2.getAddress());
		if (result != 0) {
			return result;
		}
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
		result = Integer.compare(ordinal1.intValue(), ordinal2.intValue());
		if (result != 0) {
			return result;
		}
		return 0;
	}

}
