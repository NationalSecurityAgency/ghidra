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
package ghidra.app.util.bin.format.dwarf4.next;

import static ghidra.program.model.data.DataTypeConflictHandler.ConflictResult.*;

import java.util.*;

import ghidra.program.model.data.*;
import ghidra.util.SystemUtilities;

/**
 * This {@link DataTypeConflictHandler conflict handler} attempts to match
 * conflicting {@link Composite composite data types} (structure or union) when
 * they have compatible data layouts. (Data types that are exactly equiv will
 * not be subjected to conflict handling and will never reach here)
 * <p>
 * A default/empty sized structure, or structures with the same size are
 * candidates for matching.
 * <p>
 * Structures that have a subset of the other's field definition are candidates
 * for matching.
 * <p>
 * When a candidate data type is matched with an existing data type, this
 * conflict handler will specify that the new data type is:
 * <p>
 * <ul>
 * <li>discarded and replaced by the existing data type
 * ({@link ConflictResult#USE_EXISTING})
 * <li>used to overwrite the existing data type
 * ({@link ConflictResult#REPLACE_EXISTING})
 * </ul>
 * or the candidate data type was <b>NOT</b> matched with an existing data type,
 * and the new data type is:
 * <p>
 * <ul>
 * <li>kept, but renamed with a .conflictNNNN suffix to make it unique
 * ({@link ConflictResult#RENAME_AND_ADD})
 * </ul>
 * <b>NOTE:</b> structures with alignment (instead of being statically laid out)
 * are not treated specially and will not match other aligned or non-aligned
 * structures.
 *
 */
class DWARFDataTypeConflictHandler extends DataTypeConflictHandler {

	static final DWARFDataTypeConflictHandler INSTANCE = new DWARFDataTypeConflictHandler();

	private DWARFDataTypeConflictHandler() {
		// do not create instances of this class
	}

	/**
	 * Returns true if src can overwrite the target composite based on size
	 * 
	 * @param src
	 * @param target
	 * @return
	 */
	private boolean isSizeCompatible(Composite src, Composite target) {
		return target.isNotYetDefined() || (src.getLength() == target.getLength());
	}

	/**
	 * Determines if the given composite is either empty or filled with default
	 * values (no defined components).
	 * 
	 * @param composite composite to check
	 * @return true if empty or default and false otherwise
	 */
	private boolean isCompositeDefault(Composite composite) {
		return composite.isNotYetDefined() || (composite.getNumDefinedComponents() == 0);
	}

	private boolean isCompositePart(Composite full, Composite part, Set<Long> visitedDataTypes) {
		if (full instanceof Structure && part instanceof Structure) {
			return isStructurePart((Structure) full, (Structure) part, visitedDataTypes);
		} else if (full instanceof Union && part instanceof Union) {
			return isUnionPart((Union) full, (Union) part, visitedDataTypes);
		} else {
			return false;
		}
	}

	/**
	 * Returns true if one union is a subset of another union.
	 * <p>
	 * Each component of the candidate partial union must be present in the 'full'
	 * union and must be 'equiv'.
	 * <p>
	 * Order of components is ignored, except for unnamed components, which receive
	 * a default name created using their ordinal position.
	 *
	 * @param full             {@link Union} datatype that is expected to be a
	 *                         superset of the next param.
	 * @param part             {@link Union} datatype that is expected to be a
	 *                         subset of the previous param.
	 * @param visitedDataTypes identity map of datatypes to prevent loops.
	 * @return true if part is a subset (or equal) to full.
	 */
	private boolean isUnionPart(Union full, Union part, Set<Long> visitedDataTypes) {
		if (full.getLength() < part.getLength()) {
			return false;
		}

		Map<String, DataTypeComponent> fullComponentsByName = new HashMap<>();
		for (DataTypeComponent dtc : full.getComponents()) {
			String name = dtc.getFieldName();
			if (name == null) {
				name = dtc.getDefaultFieldName();
			}
			fullComponentsByName.put(name, dtc);
		}
		for (DataTypeComponent dtc : part.getComponents()) {
			String name = dtc.getFieldName();
			if (name == null) {
				name = dtc.getDefaultFieldName();
			}
			DataTypeComponent fullDTC = fullComponentsByName.get(name);
			if (fullDTC == null) {
				return false;
			}
			DataType partDT = dtc.getDataType();
			DataType fullDT = fullDTC.getDataType();
			if (doRelaxedCompare(partDT, fullDT, visitedDataTypes) == RENAME_AND_ADD) {
				return false;
			}
		}
		return true;
	}

	/*
	 * Returns true if one structure is a partial definition of another structure.
	 * <p> Each defined component in the candidate partial structure must be present
	 * in the 'full' structure and must be equiv. <p> The order and sparseness of
	 * the candidate partial structure is not important, only that all of its
	 * defined components are present in the full structure. <p>
	 */
	private boolean isStructurePart(Structure full, Structure part, Set<Long> visitedDataTypes) {
		// Both structures should be equal in length
		if (full.getLength() != part.getLength()) {
			return false;
		}

		DataTypeComponent[] partComps = part.getDefinedComponents();

		// Find a match in the full structure's component list for each
		// component in the partial structure.
		// Use resolveConflict() == USE_EXISTING to test for equiv in addition to
		// isEquiv().
		// Ensure that two components in the partial struct don't map to the same
		// component in the full structure.
		for (DataTypeComponent partDTC : partComps) {
			DataTypeComponent fullDTCAt = (partDTC.getDataType() instanceof BitFieldDataType)
					? getBitfieldByOffsets(full, partDTC)
					: full.getComponentAt(partDTC.getOffset());
			if (fullDTCAt == null || fullDTCAt.getOffset() != partDTC.getOffset() ||
				!SystemUtilities.isEqual(fullDTCAt.getFieldName(), partDTC.getFieldName())) {
				return false;
			}
			if (!isMemberFieldPartiallyCompatible(fullDTCAt, partDTC, visitedDataTypes)) {
				return false;
			}
		}
		if ( part.getFlexibleArrayComponent() != null ) {
			return full.getFlexibleArrayComponent() != null &&
				isMemberFieldPartiallyCompatible(full.getFlexibleArrayComponent(),
					part.getFlexibleArrayComponent(), visitedDataTypes);
		}

		return true;
	}

	boolean isMemberFieldPartiallyCompatible(DataTypeComponent fullDTC, DataTypeComponent partDTC,
			Set<Long> visitedDataTypes) {
		DataType partDT = partDTC.getDataType();
		DataType fullDT = fullDTC.getDataType();
		ConflictResult dtCompResult = doRelaxedCompare(partDT, fullDT, visitedDataTypes);
		switch (dtCompResult) {
			case RENAME_AND_ADD:
				// The data type of the field in the 'full' structure is completely
				// different than the field in the 'part' structure, therefore
				// the candidate 'part' structure is not a partial definition of the full struct
				return false;
			case REPLACE_EXISTING:
				// Return true (meaning the field from the 'full' struct is the same or better
				// than the field from the 'part' structure) if the components are size compatible.
				// This is an intentionally fuzzy match to allow structures with fields
				// that are generally the same at a binary level to match.
				// For example, the same structure defined in 2 separate compile units with
				// slightly different types for the field (due to different compiler options
				// or versions or languages)
				return fullDTC.getLength() >= partDTC.getLength();
			case USE_EXISTING:
			default:
				// the data type of the field in the 'full' structure is the same as
				// or a better version of the field in the 'part' structure.
				return true;
		}

	}

	private DataTypeComponent getBitfieldByOffsets(Structure full, DataTypeComponent partDTC) {
		BitFieldDataType partBF = (BitFieldDataType) partDTC.getDataType();

		DataTypeComponent fullDTC = full.getComponentAt(partDTC.getOffset());
		if (fullDTC == null) {
			return null;
		}
		
		int fullNumComp = full.getNumComponents();
		for(int fullOrdinal = fullDTC.getOrdinal(); fullOrdinal < fullNumComp; fullOrdinal++) {
			fullDTC = full.getComponent(fullOrdinal);
			if (!(fullDTC.getDataType() instanceof BitFieldDataType) ||
				fullDTC.getOffset() > partDTC.getOffset()) {
				break;
			}
			BitFieldDataType fullBF = (BitFieldDataType) fullDTC.getDataType();
			if (fullDTC.getOffset() == partDTC.getOffset() &&
				fullBF.getBitOffset() == partBF.getBitOffset() &&
				fullBF.getBitSize() == partBF.getBitSize()) {
				return fullDTC;
			}
		}

		return null;
	}

	/*
	 * Strict compare will compare its parameters. The contents of these datatypes
	 * (ie. contents of structs, pointers, arrays) will be compared with relaxed
	 * typedef checking.
	 */
	private ConflictResult doStrictCompare(DataType addedDataType, DataType existingDataType,
			Set<Long> visitedDataTypes) {
		if (addedDataType == existingDataType ||
			!addVisited(existingDataType, addedDataType, visitedDataTypes)) {
			return USE_EXISTING;
		}

		if (existingDataType instanceof Composite && addedDataType instanceof Composite) {
			Composite existingComposite = (Composite) existingDataType;
			Composite addedComposite = (Composite) addedDataType;

			// Check to see if we are adding a default/empty data type
			if ((isCompositeDefault(addedComposite)) && isSizeCompatible(existingComposite, addedComposite)) {
				return USE_EXISTING;
			}
			// Check to see if the existing type is a default/empty data type
			if ((isCompositeDefault(existingComposite)) && isSizeCompatible(addedComposite, existingComposite)) {
				return REPLACE_EXISTING;
			}
			// Check to see if the added type is part of the existing type first to
			// generate more USE_EXISTINGS when possible.
			if (isCompositePart(existingComposite, addedComposite, visitedDataTypes)) {
				return USE_EXISTING;
			}
			// Check to see if the existing type is a part of the added type
			if (isCompositePart(addedComposite, existingComposite, visitedDataTypes)) {
				return REPLACE_EXISTING;
			}

			return RENAME_AND_ADD;
		}

		if (existingDataType instanceof TypeDef && addedDataType instanceof TypeDef) {
			TypeDef addedTypeDef = (TypeDef) addedDataType;
			TypeDef existingTypeDef = (TypeDef) existingDataType;
			return doRelaxedCompare(addedTypeDef.getBaseDataType(), existingTypeDef.getBaseDataType(),
					visitedDataTypes);
		}

		if (existingDataType instanceof Array && addedDataType instanceof Array) {
			Array addedArray = (Array) addedDataType;
			Array existingArray = (Array) existingDataType;

			if (addedArray.getNumElements() != existingArray.getNumElements()
					|| addedArray.getElementLength() != existingArray.getElementLength()) {
				return RENAME_AND_ADD;
			}

			return doRelaxedCompare(addedArray.getDataType(), existingArray.getDataType(), visitedDataTypes);
		}

		if (existingDataType instanceof Pointer && addedDataType instanceof Pointer) {
			return doRelaxedCompare(((Pointer) addedDataType).getDataType(), ((Pointer) existingDataType).getDataType(),
					visitedDataTypes);
		}

		if (existingDataType instanceof FunctionDefinition && addedDataType instanceof FunctionDefinition) {
			return compareFuncDef((FunctionDefinition) addedDataType, (FunctionDefinition) existingDataType,
					visitedDataTypes);
		}

		if (existingDataType instanceof BitFieldDataType && addedDataType instanceof BitFieldDataType) {
			BitFieldDataType existingBF = (BitFieldDataType) existingDataType;
			BitFieldDataType addedBF = (BitFieldDataType) addedDataType;
			if (existingBF.getDeclaredBitSize() != addedBF.getDeclaredBitSize()) {
				return RENAME_AND_ADD;
			}
			return existingBF.getPrimitiveBaseDataType().isEquivalent(addedBF.getPrimitiveBaseDataType()) ? USE_EXISTING
					: RENAME_AND_ADD;
		}

		if (existingDataType.isEquivalent(addedDataType)) {
			return USE_EXISTING;
		}

		return RENAME_AND_ADD;
	}

	private ConflictResult compareFuncDef(FunctionDefinition addedFunc, FunctionDefinition existingFunc,
			Set<Long> visitedDataTypes) {
		if (doRelaxedCompare(addedFunc.getReturnType(), existingFunc.getReturnType(),
				visitedDataTypes) == RENAME_AND_ADD) {
			return RENAME_AND_ADD;
		}
		ParameterDefinition[] addedArgs = addedFunc.getArguments();
		ParameterDefinition[] existingArgs = existingFunc.getArguments();

		if (addedArgs.length != existingArgs.length) {
			return RENAME_AND_ADD;
		}

		for (int i = 0; i < addedArgs.length; i++) {
			ParameterDefinition addedParam = addedArgs[i];
			ParameterDefinition existingParam = existingArgs[i];

			if (doRelaxedCompare(addedParam.getDataType(), existingParam.getDataType(),
					visitedDataTypes) == RENAME_AND_ADD) {
				return RENAME_AND_ADD;
			}
		}

		return USE_EXISTING;
	}

	/*
	 * Relaxed compare will take liberties in skipping typedefs to try to compare
	 * the types that the typedef are hiding. This is useful when comparing types
	 * that were embedded in differently compiled files, where you might end up with
	 * a raw basetype in one file and a typedef to a basetype in another file.
	 */
	private ConflictResult doRelaxedCompare(DataType addedDataType, DataType existingDataType,
			Set<Long> visitedDataTypes) {

		// unwrap typedefs, possibly asymmetrically. (ie. only unwrap added vs.
		// existing)
		if (addedDataType instanceof TypeDef) {
			return doRelaxedCompare(((TypeDef) addedDataType).getBaseDataType(), existingDataType, visitedDataTypes);
		}
		if (existingDataType instanceof TypeDef) {
			return doRelaxedCompare(addedDataType, ((TypeDef) existingDataType).getBaseDataType(), visitedDataTypes);
		}

		return doStrictCompare(addedDataType, existingDataType, visitedDataTypes);
	}

	private long getDTPairKey(DataType dataType1, DataType dataType2) {
		return ((long) System.identityHashCode(dataType1) << 32)
				+ (System.identityHashCode(dataType2) & 0xffffffffL);
	}

	private boolean addVisited(DataType dataType1, DataType dataType2, Set<Long> visitedDataTypes) {
		long key = getDTPairKey(dataType1, dataType2);
		return visitedDataTypes.add(key);
	}

	@Override
	public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
		Set<Long> visitedDataTypes = new HashSet<>();
		return doStrictCompare(addedDataType, existingDataType, visitedDataTypes);
	}

	@Override
	public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
		return false;
	}

	@Override
	public DataTypeConflictHandler getSubsequentHandler() {
		return this;
	}

}
