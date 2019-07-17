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
package ghidra.program.model.data;

import java.util.*;

import ghidra.util.Msg;

public abstract class DataTypeConflictHandler {

	/**
	 * <code>ConflictResolutionPolicy</code> indicates the conflict resolution policy
	 * which should be applied when any conflict is encountered
	 */
	public static enum ConflictResolutionPolicy {
		RENAME_AND_ADD {
			@Override
			public DataTypeConflictHandler getHandler() {
				return DEFAULT_HANDLER;
			}
		},
		USE_EXISTING {
			@Override
			public DataTypeConflictHandler getHandler() {
				return KEEP_HANDLER;
			}
		},
		REPLACE_EXISTING {
			@Override
			public DataTypeConflictHandler getHandler() {
				return REPLACE_HANDLER;
			}
		},
		REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD {
			@Override
			public DataTypeConflictHandler getHandler() {
				return REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER;
			}
		};
		public abstract DataTypeConflictHandler getHandler();
	}

	/**
	 * <code>ConflictResult</code> indicates the resolution which should be
	 * applied to a specific conflict
	 */
	public static enum ConflictResult {
		RENAME_AND_ADD, USE_EXISTING, REPLACE_EXISTING;
	}

	/**
	 * Due to the locking concerns which can arise with a DataTypeConflictHandler,
	 * definition of new implementations must be done here.
	 */
	private DataTypeConflictHandler() {
	}

	public final static DataTypeConflictHandler DEFAULT_HANDLER = new DataTypeConflictHandler() {
		@Override
		public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
			Msg.info(this,
				"Conflict with existing type " + existingDataType.getName() + "(" +
					existingDataType.getDescription() +
					"), new type will be renamed with .conflict suffix");
			return ConflictResult.RENAME_AND_ADD;
		}

		@Override
		public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
			return true;
		}

		@Override
		public DataTypeConflictHandler getSubsequentHandler() {
			return DEFAULT_SUBSEQUENT_HANDLER;
		}
	};

	private final static DataTypeConflictHandler DEFAULT_SUBSEQUENT_HANDLER =
		new DataTypeConflictHandler() {
			@Override
			public ConflictResult resolveConflict(DataType addedDataType,
					DataType existingDataType) {
				return DEFAULT_HANDLER.resolveConflict(addedDataType, existingDataType);
			}

			@Override
			public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
				return false;
			}

			@Override
			public DataTypeConflictHandler getSubsequentHandler() {
				return this;
			}
		};

	public static DataTypeConflictHandler REPLACE_HANDLER = new DataTypeConflictHandler() {
		@Override
		public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
//			Msg.info(
//				this,
//				"Replacing type " + existingDataType.getName() + "(" +
//					existingDataType.getDescription() + ") with " + addedDataType.getName() + "(" +
//					addedDataType.getDescription() + ")");
			return ConflictResult.REPLACE_EXISTING;
		}

		@Override
		public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
			return true;
		}

		@Override
		public DataTypeConflictHandler getSubsequentHandler() {
			return SUBSEQUENT_REPLACE_HANDLER;
		}
	};
	private final static DataTypeConflictHandler SUBSEQUENT_REPLACE_HANDLER =
		new DataTypeConflictHandler() {
			@Override
			public ConflictResult resolveConflict(DataType addedDataType,
					DataType existingDataType) {
				return REPLACE_HANDLER.resolveConflict(addedDataType, existingDataType);
			}

			@Override
			public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
				return false;
			}

			@Override
			public DataTypeConflictHandler getSubsequentHandler() {
				return this;
			}
		};

	public final static DataTypeConflictHandler KEEP_HANDLER = new DataTypeConflictHandler() {
		@Override
		public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
			Msg.info(this, "New type not added in favor of existing type " +
				existingDataType.getName() + "(" + existingDataType.getDescription() + ")");
			return ConflictResult.USE_EXISTING;
		}

		@Override
		public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
			return false;
		}

		@Override
		public DataTypeConflictHandler getSubsequentHandler() {
			return this;
		}
	};

	/**
	 * This {@link DataTypeConflictHandler conflict handler} attempts to match conflicting
	 * {@link Composite composite data types} (structure or union) when they have compatible
	 * data layouts.  (Data types that are exactly equiv will not be subjected to conflict
	 * handling and will never reach here)
	 * <p>
	 * A default/empty sized structure, or structures with the same size are candidates
	 * for matching.
	 * <p>
	 * Structures that have a subset of the other's field definition are candidates for matching.
	 * <p>
	 * When a candidate data type is matched with an existing data type, this conflict handler
	 * will specify that the new data type is:<p>
	 * <ul>
	 * <li>discarded and replaced by the existing data type ({@link ConflictResult#USE_EXISTING})
	 * <li>used to overwrite the existing data type ({@link ConflictResult#REPLACE_EXISTING})
	 * </ul>
	 * or the candidate data type was <b>NOT</b> matched with an existing data type, and the new data type is:<p>
	 * <ul>
	 * <li>kept, but renamed with a .conflictNNNN suffix to make it unique ({@link ConflictResult#RENAME_AND_ADD})
	 * </ul>
	 * <b>NOTE:</b> structures with alignment (instead of being statically laid out) are not
	 * treated specially and will not match other aligned or non-aligned structures.
	 *
	 */
	public final static DataTypeConflictHandler REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER =
		new DataTypeConflictHandler() {

			/**
			 * Returns true if src can overwrite the target composite based on size
			 * @param src
			 * @param target
			 * @return
			 */
			private boolean isSizeCompatible(Composite src, Composite target) {
				return (target.getLength() <= 1) || (src.getLength() == target.getLength());
			}

			/**
			 * Returns true if the {@link Composite composite} is empty (to get around the lying that
			 * {@link Composite#getLength()} does.)
			 * @param composite
			 * @return
			 */
			private boolean isCompositeEmpty(Composite composite) {
				return composite.getLength() <= 1 && composite.getNumComponents() == 0;
			}

			/**
			 * Determines if the given composite is filled with default values (all components are default).
			 * @param composite composite to check
			 * @return true if default and false otherwise
			 */
			private boolean isCompositeDefault(Composite composite) {
				if (composite.getLength() == composite.getNumComponents()) {
					DataTypeComponent[] comps = composite.getComponents();
					boolean isDefault = true;
					for (int i = 0; i < comps.length; i++) {
						if (comps[i].getDataType() != DataType.DEFAULT) {
							isDefault = false;
							break;
						}
					}
					if (isDefault) {
						return true;
					}
				}
				return false;
			}

			private boolean isCompositePart(Composite full, Composite part,
					Map<DataType, DataType> visitedDataTypes) {
				if (full instanceof Structure && part instanceof Structure) {
					return isStructurePart((Structure) full, (Structure) part, visitedDataTypes);
				}
				else if (full instanceof Union && part instanceof Union) {
					return isUnionPart((Union) full, (Union) part, visitedDataTypes);
				}
				else {
					return false;
				}
			}

			/**
			 * Returns true if one union is a subset of another union.
			 * <p>
			 * Each component of the candidate partial union must be present in the
			 * 'full' union and must be 'equiv'.
			 * <p>
			 * Order of components is ignored, except for unnamed components, which receive
			 * a default name created using their ordinal position.
			 *
			 * @param full {@link Union} datatype that is expected to be a superset of the next param.
			 * @param part {@link Union} datatype that is expected to be a subset of the previous param.
			 * @param visitedDataTypes identity map of datatypes to prevent loops.
			 * @return true if part is a subset (or equal) to full.
			 */
			private boolean isUnionPart(Union full, Union part,
					Map<DataType, DataType> visitedDataTypes) {
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
					if (doRelaxedCompare(partDT, fullDT,
						visitedDataTypes) == ConflictResult.RENAME_AND_ADD) {
						return false;
					}
				}
				return true;
			}

			/*
			 * Returns true if one structure is a partial definition of another structure.
			 * <p>
			 * Each defined component in the candidate partial structure must be present
			 * in the 'full' structure and must be equiv.
			 * <p>
			 * The order and sparseness of the candidate partial structure is not important,
			 * only that all of its defined components are present in the full structure.
			 * <p>
			 */
			private boolean isStructurePart(Structure full, Structure part,
					Map<DataType, DataType> visitedDataTypes) {
				// Both structures should be equal in length
				if (full.getLength() != part.getLength()) {
					return false;
				}

				boolean[] fullCompsUsedFlag = new boolean[full.getComponents().length];
				DataTypeComponent[] partComps = part.getDefinedComponents();

				// Find a match in the full structure's component list for each
				// component in the partial structure.
				// Use resolveConflict() == USE_EXISTING to test for equiv in addition to
				// isEquiv().
				// Ensure that two components in the partial struct don't map to the same
				// component in the full structure.
				for (int i = 0; i < partComps.length; i++) {
					DataTypeComponent partDTC = partComps[i];
					DataTypeComponent fullDTCAt = full.getComponentAt(partDTC.getOffset());
					int fullOrd = fullDTCAt.getOrdinal();
					if (fullCompsUsedFlag[fullOrd]) {
						return false;
					}
					DataType partDT = partDTC.getDataType();
					DataType fullDT = fullDTCAt.getDataType();
					if (doRelaxedCompare(partDT, fullDT,
						visitedDataTypes) == ConflictResult.RENAME_AND_ADD) {
						return false;
					}
					fullCompsUsedFlag[fullOrd] = true;
				}

				return true;
			}

			/*
			 * Strict compare will compare its parameters.
			 * The contents of these datatypes (ie. contents of structs, pointers, arrays)
			 * will be compared with relaxed typedef checking.
			 */
			private ConflictResult doStrictCompare(DataType addedDataType,
					DataType existingDataType, Map<DataType, DataType> visitedDataTypes) {
				visitedDataTypes.put(existingDataType, addedDataType);
				if (existingDataType.isEquivalent(addedDataType)) {
					return ConflictResult.USE_EXISTING;
				}
				else if (existingDataType instanceof Composite &&
					addedDataType instanceof Composite) {
					Composite existingComposite = (Composite) existingDataType;
					Composite addedComposite = (Composite) addedDataType;

					// Check to see if we are adding a default/empty data type
					if ((isCompositeEmpty(addedComposite) || isCompositeDefault(addedComposite)) &&
						isSizeCompatible(existingComposite, addedComposite)) {
						return ConflictResult.USE_EXISTING;
					}
					// Check to see if the existing type is a default/empty data type
					if ((isCompositeEmpty(existingComposite) ||
						isCompositeDefault(existingComposite)) &&
						isSizeCompatible(addedComposite, existingComposite)) {
						return ConflictResult.REPLACE_EXISTING;
					}
					// Check to see if the added type is part of the existing type first to
					// generate more USE_EXISTINGS when possible.
					if (isCompositePart(existingComposite, addedComposite, visitedDataTypes)) {
						return ConflictResult.USE_EXISTING;
					}
					// Check to see if the existing type is a part of the added type
					if (isCompositePart(addedComposite, existingComposite, visitedDataTypes)) {
						return ConflictResult.REPLACE_EXISTING;
					}
				}
				else if (existingDataType instanceof TypeDef && addedDataType instanceof TypeDef) {
					TypeDef addedTypeDef = (TypeDef) addedDataType;
					TypeDef existingTypeDef = (TypeDef) existingDataType;
					return doRelaxedCompare(addedTypeDef.getBaseDataType(),
						existingTypeDef.getBaseDataType(), visitedDataTypes);
				}
				else if (existingDataType instanceof Array && addedDataType instanceof Array) {
					Array addedArray = (Array) addedDataType;
					Array existingArray = (Array) existingDataType;

					if (addedArray.getNumElements() != existingArray.getNumElements() ||
						addedArray.getElementLength() != existingArray.getElementLength()) {
						return ConflictResult.RENAME_AND_ADD;
					}

					return doRelaxedCompare(addedArray.getDataType(), existingArray.getDataType(),
						visitedDataTypes);
				}

				return ConflictResult.RENAME_AND_ADD;
			}

			/*
			 * Relaxed compare will take liberties in skipping typedefs to try to compare
			 * the types that the typedef are hiding.  This is useful when comparing types
			 * that were embedded in differently compiled files, where you might end up with
			 * a raw basetype in one file and a typedef to a basetype in another file.
			 */
			private ConflictResult doRelaxedCompare(DataType addedDataType,
					DataType existingDataType, Map<DataType, DataType> visitedDataTypes) {

				if (existingDataType instanceof Pointer && addedDataType instanceof Pointer) {
					DataType ptrAddedDataType = ((Pointer) addedDataType).getDataType();
					DataType ptrExistingDataType = ((Pointer) existingDataType).getDataType();
					// only descend into the pointed-to-type if we haven't looked at it before.
					// if you don't do this, you will have a stack-overflow issue when a struct
					// has a pointer to its same type.
					if (!visitedDataTypes.containsKey(ptrExistingDataType)) {
						visitedDataTypes.put(ptrExistingDataType, ptrAddedDataType);
						addedDataType = ptrAddedDataType;
						existingDataType = ptrExistingDataType;
					}

				}
				// unwrap typedefs, possibly asymmetrically. (ie. only unwrap added vs. existing)
				if (addedDataType instanceof TypeDef) {
					addedDataType = ((TypeDef) addedDataType).getBaseDataType();
				}
				if (existingDataType instanceof TypeDef) {
					existingDataType = ((TypeDef) existingDataType).getBaseDataType();
				}
				return doStrictCompare(addedDataType, existingDataType, visitedDataTypes);
			}

			@Override
			public ConflictResult resolveConflict(DataType addedDataType,
					DataType existingDataType) {
				IdentityHashMap<DataType, DataType> visitedDataTypes = new IdentityHashMap<>();
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
		};

	final static DataTypeConflictHandler BUILT_IN_MANAGER_HANDLER = new DataTypeConflictHandler() {
		@Override
		public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
			throw new UnsupportedOperationException(
				"Built-in data-types may not be substantially changed while Ghidra is running");
		}

		@Override
		public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
			return false;
		}

		@Override
		public DataTypeConflictHandler getSubsequentHandler() {
			return this;
		}
	};

	/**
	 * Callback to handle conflicts in a datatype manager when new datatypes are added that
	 * have the same name as an existing datatype. The implementer of this interface should do
	 * one of the following:
	 * 		return the addedDataType - which means to replace the existingDataType with the addedDataType
	 * 							(may throw exception if the datatypes are not compatible)
	 * 		return the existingDataType the addedDataType will be ignored and the existing dataType will
	 * 							be used.
	 * 		return a new DataType with a new name/category
	 * @param addedDataType the datatype being added.
	 * @param existingDataType the datatype that exists with the same name/category as the one added
	 * @return an enum specify how to handle the conflict
	 */
	public abstract ConflictResult resolveConflict(DataType addedDataType,
			DataType existingDataType);

	/**
	 * Callback invoked when an associated dataType is being resolved and its local version of the
	 * dataType is different from the source archive's dataType.  This method returns true if the
	 * local version should be updated to the archive's version of the dataType.  Otherwise, the
	 * local dataType will be used (without updating) in the resolve operation.
	 * @param sourceDataType
	 * @param localDataType
	 * @return true if the localDataType should be updated to be equivalent to the sourceDataType.
	 */
	public abstract boolean shouldUpdate(DataType sourceDataType, DataType localDataType);

	/**
	 * Returns the appropriate handler for recursive resolve calls.
	 */
	public abstract DataTypeConflictHandler getSubsequentHandler();

}
