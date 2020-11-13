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

	public final static DataTypeConflictHandler DEFAULT_HANDLER = new DataTypeConflictHandler() {
		@Override
		public ConflictResult resolveConflict(DataType addedDataType, DataType existingDataType) {
//			Msg.info(this,
//				"Conflict with existing type " + existingDataType.getName() + "(" +
//					existingDataType.getDescription() +
//					"), new type will be renamed with .conflict suffix");
			return ConflictResult.RENAME_AND_ADD;
		}

		@Override
		public boolean shouldUpdate(DataType sourceDataType, DataType localDataType) {
			return true;  // TODO: uncertain this is appropriate
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
//			Msg.info(this, "New type not added in favor of existing type " +
//				existingDataType.getName() + "(" + existingDataType.getDescription() + ")");
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
	 * This {@link DataTypeConflictHandler conflict handler} behaves similar to 
	 * the {@link #DEFAULT_HANDLER} with the difference being that a 
	 * empty composite (see {@link Composite#isNotYetDefined()}) will be 
	 * replaced by a similar non-empty composite type.  Alignment (e.g., packing)
	 * is not considered when determining conflict resolution.
	 * <br>
	 * For datatypes originating from a source archive with matching ID, the 
	 * replacment strategy will utilize the implementation with the 
	 * latest timestamp.
	 * <br>
	 * Unlike the {@link #DEFAULT_HANDLER}, follow-on dependency datatype 
	 * resolutions will retain the same conflict resolution strategy.
	 */
	public final static DataTypeConflictHandler REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER =
		new DataTypeConflictHandler() {

			private ConflictResult resolveConflictReplaceEmpty(DataType addedDataType,
					DataType existingDataType) {
				if (addedDataType.isNotYetDefined()) {
					return ConflictResult.USE_EXISTING;
				}
				if (existingDataType.isNotYetDefined()) {
					return ConflictResult.REPLACE_EXISTING;
				}
				return ConflictResult.RENAME_AND_ADD;
			}

			@Override
			public ConflictResult resolveConflict(DataType addedDataType,
					DataType existingDataType) {
				if (addedDataType instanceof Structure) {
					if (existingDataType instanceof Structure) {
						return resolveConflictReplaceEmpty(addedDataType, existingDataType);
					}
				}
				else if (addedDataType instanceof Union) {
					if (existingDataType instanceof Union) {
						return resolveConflictReplaceEmpty(addedDataType, existingDataType);
					}
				}
				return ConflictResult.RENAME_AND_ADD;
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
