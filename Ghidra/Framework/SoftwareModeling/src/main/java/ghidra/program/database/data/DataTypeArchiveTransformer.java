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
package ghidra.program.database.data;

import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.util.*;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.framework.DockingApplicationConfiguration;
import docking.widgets.label.GDLabel;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.Enum;
import ghidra.util.*;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.*;
import ghidra.util.task.*;

/**
 * DataTypeArchiveTransformer changes (transforms) a new archive file so that it appears to be
 * an updated copy of a previously existing data type archive. This allows us to parse a new
 * version of each standard GDT file we supply. This class changes the IDs on the data types
 * so they will match the previous version's IDs. This allows the new data type archive and
 * its data types to become the associated data types where the previous version data types
 * were applied.
 */
public class DataTypeArchiveTransformer implements GhidraLaunchable {

	public static void transform(File oldFile, File newFile, File destinationFile,
			boolean useOldFileID, TaskMonitor monitor)
			throws InvalidInputException, DuplicateFileException, IOException, CancelledException {

		monitor.setMessage("Beginning transformation...");
		validate(oldFile, newFile, destinationFile);

		FileDataTypeManager oldFileArchive = null;
		FileDataTypeManager newFileArchive = null;
		try {
			monitor.initialize(100);
			oldFileArchive = FileDataTypeManager.openFileArchive(oldFile, false);
			newFileArchive = FileDataTypeManager.openFileArchive(newFile, true);
			UniversalID oldUniversalID = oldFileArchive.getUniversalID();
			UniversalID newUniversalID = newFileArchive.getUniversalID();
			Msg.info(DataTypeArchiveTransformer.class, "Old file ID = " + oldUniversalID);
			Msg.info(DataTypeArchiveTransformer.class, "New file ID = " + newUniversalID);
			transformEachDataType(oldFileArchive, newFileArchive, monitor);
			monitor.setProgress(50);
			fixEachDataTypeTimestamp(oldFileArchive, newFileArchive, monitor);
			monitor.setProgress(100);
			monitor.setMessage("Saving " + destinationFile.getAbsolutePath());
			if (useOldFileID) {
				saveNewArchive(oldFileArchive, newFileArchive, destinationFile);
			}
			else {
				saveNewArchive(newFileArchive, destinationFile);
			}
		}
		finally {
			if (oldFileArchive != null) {
				oldFileArchive.close();
			}
			if (newFileArchive != null) {
				newFileArchive.close();
			}
		}
	}

	private static void validate(File oldFile, File newFile, File destinationFile)
			throws InvalidInputException {

		if (oldFile == null || oldFile.getPath().length() == 0) {
			throw new InvalidInputException("Old data type archive file must be specified.");
		}
		if (newFile == null || newFile.getPath().length() == 0) {
			throw new InvalidInputException("New data type archive file must be specified.");
		}
		if (destinationFile == null || destinationFile.getPath().length() == 0) {
			throw new InvalidInputException(
				"Destination data type archive file must be specified.");
		}

		if (!oldFile.getPath().endsWith(FileDataTypeManager.SUFFIX)) {
			throw new InvalidInputException("Old data type archive file must end with .gdt");
		}
		if (!newFile.getPath().endsWith(FileDataTypeManager.SUFFIX)) {
			throw new InvalidInputException("New data type archive file must end with .gdt");
		}
		if (!destinationFile.getPath().endsWith(FileDataTypeManager.SUFFIX)) {
			throw new InvalidInputException(
				"Destination data type archive file must end with .gdt");
		}

		if (!oldFile.exists()) {
			throw new InvalidInputException("Old data type archive file must already exist.");
		}
		if (!newFile.exists()) {
			throw new InvalidInputException("New data type archive file must already exist.");
		}

		if (!oldFile.isFile()) {
			throw new InvalidInputException("Old data type archive file must be a file.");
		}
		if (!newFile.isFile()) {
			throw new InvalidInputException("New data type archive file must be a file.");
		}

		if (oldFile.length() == 0) {
			throw new InvalidInputException("Old data type archive file cannot be empty.");
		}
		if (newFile.length() == 0) {
			throw new InvalidInputException("New data type archive file cannot be empty.");
		}

		if (destinationFile.exists()) {
			throw new InvalidInputException("Destination file \"" +
				destinationFile.getAbsolutePath() + "\" cannot already exist.");
		}

	}

	private static void transformEachDataType(FileDataTypeManager oldFileArchive,
			FileDataTypeManager newFileArchive, TaskMonitor monitor) throws CancelledException {
		boolean commit = false;
		int transactionID = newFileArchive.startTransaction("Transforming Data Type Archive");
		try {
			// Guarantee that the data type IDs won't already match those in the old archive.
			// This is necessary if we re-run the transformer for an archive.
			assignNewUniversalIDs(newFileArchive, monitor);

			// Perform an initial pass to match by path name if possible and check for
			// anonymous data types that matched by matching components.
			Iterator<DataType> allDataTypes = newFileArchive.getAllDataTypes();
			while (allDataTypes.hasNext()) {
				monitor.checkCanceled();
				DataType newDataType = allDataTypes.next();
				if (isAnonymousType(newDataType)) {
					// Skip anonymous types, they are matched as components of composites or
					// later unmatched enums are matched in categories.
					continue;
				}
				if (newDataType instanceof Pointer || newDataType instanceof Array ||
					newDataType instanceof BuiltIn) {
					continue; // Skip pointer array or builtin.
				}
				DataType oldDataType =
					transformDataType(newDataType, oldFileArchive, newFileArchive);

				// Now process children anonymous data types for composites.
				processAnonymous(oldDataType, newDataType, oldFileArchive, newFileArchive);

//				monitor.incrementProgress(1);
				monitor.setMessage("Transforming ID for " + newDataType.getPathName());
			}

			// Process any unmatched enums by trying to match within each matching category.
			processUnmatchedEnums(oldFileArchive, newFileArchive, monitor);

			commit = true;
		}
		finally {
			newFileArchive.endTransaction(transactionID, commit);
		}
	}

	private static void assignNewUniversalIDs(FileDataTypeManager newFileArchive,
			TaskMonitor monitor) throws CancelledException {

		Iterator<DataType> allDataTypes = newFileArchive.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			monitor.checkCanceled();
			DataType newDataType = allDataTypes.next();
			if (newDataType instanceof DataTypeDB) {
				((DataTypeDB) newDataType).setUniversalID(UniversalIdGenerator.nextID());
			}
		}
	}

	private static void processUnmatchedEnums(FileDataTypeManager oldFileArchive,
			FileDataTypeManager newFileArchive, TaskMonitor monitor) throws CancelledException {

		// Find all anonymous enums and if not already matched to a data type in the old
		// archive, then try to match with an anonymous enum in the same category of the
		// old archive.
		Iterator<DataType> allDataTypes = newFileArchive.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			monitor.checkCanceled();
			DataType newDataType = allDataTypes.next();
			if (newDataType instanceof Enum && isAnonymousType(newDataType)) {

				// Does this new data type already match one in the old archive?
				UniversalID newDtUniversalID = newDataType.getUniversalID();
				DataType matchingDt = oldFileArchive.findDataTypeForID(newDtUniversalID);
				if (matchingDt != null) {
					continue; // Already matched.
				}

				// Find the matching anonymous in the old archive under the same category.
				Enum oldEnum = findMatchingAnonEnum((Enum) newDataType, oldFileArchive);
				if (oldEnum != null && areSameClassType(newDataType, oldEnum)) {
					// Found a match so set the ID.
					transformDataType(newDataType, newFileArchive, oldEnum);
				}
			}
		}
	}

	private static Enum findMatchingAnonEnum(Enum newEnum, FileDataTypeManager oldFileArchive) {

		CategoryPath categoryPath = newEnum.getCategoryPath();
		Category category = oldFileArchive.getCategory(categoryPath);
		if (category == null) {
			return null;
		}
		DataType[] dataTypes = category.getDataTypes();
		for (DataType oldDataType : dataTypes) {
			if (oldDataType instanceof Enum && isAnonymousType(oldDataType)) {
				// Got an anonymous enum so compare the names.
				Enum oldEnum = (Enum) oldDataType;
				if (isMatchingEnum(newEnum, oldEnum)) {
					return oldEnum;
				}
			}
		}
		return null;
	}

	private static boolean isMatchingEnum(Enum newEnum, Enum oldEnum) {
		String[] names = newEnum.getNames();
		int totalNames = names.length;
		int nameMatches = 0;
		int exactMatches = 0;
		for (String name : names) {
			try {
				long newValue = newEnum.getValue(name);
				try {
					long oldValue = oldEnum.getValue(name);
					nameMatches++;
					if (newValue == oldValue) {
						exactMatches++;
					}
				}
				catch (NoSuchElementException e) {
					// Name didn't match so don't count.
				}
			}
			catch (NoSuchElementException e1) {
				Msg.error(DataTypeArchiveTransformer.class, "Couldn't get the value for the name " +
					name + " in enum " + newEnum.getName());
			}
		}
		// For now, this expects to match at least half of the name value pairs in the new enum.
		int threshold = totalNames / 2; // 50%
		if (exactMatches > 0 && exactMatches >= threshold) {
			return true;
		}
		if (nameMatches > 0) {
			Msg.info(DataTypeArchiveTransformer.class, "Enum " + newEnum.getName() + " had " +
				nameMatches + " name matches with " + oldEnum.getName());
		}
		return false;
	}

	private static void processAnonymous(DataType oldDataType, DataType newDataType,
			FileDataTypeManager oldFileArchive, FileDataTypeManager newFileArchive) {

		// If we have composites, then get any component with an anonymous data type in the
		// newDataType, and look for it by matching field name in the old composite.
		// If the composites are anonymous then look for matching components by ordinal
		// if the number of components matches.
		if (newDataType instanceof Composite && oldDataType instanceof Composite) {
			Composite newComposite = (Composite) newDataType;
			Composite oldComposite = (Composite) oldDataType;
			boolean isNewDtAnonymous = isAnonymousType(newDataType);
			boolean isOldDtAnonymous = isAnonymousType(oldDataType);
			if (isNewDtAnonymous && isOldDtAnonymous) {
				if (newComposite.getNumComponents() != oldComposite.getNumComponents()) {
					// Don't match anonymous components if the number of components
					// differs in anonymous composite data types.
					return;
				}
			}
			DataTypeComponent[] newComponents = newComposite.getComponents();
			for (DataTypeComponent newComp : newComponents) {
				transformAnonymousComponent(oldFileArchive, newFileArchive, oldComposite,
					newComposite, newComp);
			}
		}
		else if (newDataType instanceof TypeDef && oldDataType instanceof TypeDef) {
			// Is this a TypeDef on an anonymous?
			TypeDef oldTypeDef = (TypeDef) oldDataType;
			TypeDef newTypeDef = (TypeDef) newDataType;
			transformInnerAnonymousDataType(oldTypeDef.getDataType(), newTypeDef.getDataType(),
				oldFileArchive, newFileArchive);
		}
		else if (newDataType instanceof Pointer && oldDataType instanceof Pointer) {
			// Is this pointer to an anonymous?
			Pointer oldPointer = (Pointer) oldDataType;
			Pointer newPointer = (Pointer) newDataType;
			transformInnerAnonymousDataType(oldPointer.getDataType(), newPointer.getDataType(),
				oldFileArchive, newFileArchive);
		}
		else if (newDataType instanceof Array && oldDataType instanceof Array) {
			// Is this an array of anonymous?
			Array oldArray = (Array) oldDataType;
			Array newArray = (Array) newDataType;
			if (oldArray.getNumElements() == newArray.getNumElements()) {
				transformInnerAnonymousDataType(oldArray.getDataType(), newArray.getDataType(),
					oldFileArchive, newFileArchive);
			}
		}
	}

	private static void transformAnonymousComponent(FileDataTypeManager oldFileArchive,
			FileDataTypeManager newFileArchive, Composite oldComposite, Composite newComposite,
			DataTypeComponent newComponent) {

		DataType newCompDt = newComponent.getDataType();
		int anonymousPointerDepth = getAnonymousPointerDepth(newCompDt);
		int anonymousArrayNumElements = getAnonymousArrayElementCount(newCompDt);
		int anonymousTypeDefDepth = getAnonymousTypeDefDepth(newCompDt);

		if (isAnonymousType(newCompDt) || anonymousPointerDepth > 0 ||
			anonymousArrayNumElements > 0 || anonymousTypeDefDepth > 0) {

			// Found an anonymous type, anonymous pointer, or anonymous array,
			// so get the matching component by field name or ordinal.
			DataTypeComponent matchingComponent =
				getAnonymousMatch(oldComposite, newComposite, newComponent);

			if (matchingComponent != null) {
				DataType oldCompDt = matchingComponent.getDataType();
				// Pointer
				if (anonymousPointerDepth > 0) {
					int oldPointerDepth = getAnonymousPointerDepth(oldCompDt);
					if (anonymousPointerDepth != oldPointerDepth) {
						return; // No match for anonymous pointer.
					}
					// Get each anonymous type rather than the pointer.
					newCompDt = DataTypeUtilities.getBaseDataType(newCompDt);
					oldCompDt = DataTypeUtilities.getBaseDataType(oldCompDt);
				}
				// Array
				if (anonymousArrayNumElements > 0) {
					int oldArrayNumElements = getAnonymousArrayElementCount(oldCompDt);
					if (anonymousArrayNumElements != oldArrayNumElements) {
						return; // No match for anonymous array.
					}
					// Get each anonymous type rather than the array.
					newCompDt = DataTypeUtilities.getBaseDataType(newCompDt);
					oldCompDt = DataTypeUtilities.getBaseDataType(oldCompDt);
				}
				// TypeDef
				if (anonymousTypeDefDepth > 0) {
					int oldTypeDefDepth = getAnonymousTypeDefDepth(oldCompDt);
					if (anonymousTypeDefDepth != oldTypeDefDepth) {
						return; // No match for anonymous type definition.
					}
					// Get each anonymous type rather than the typedef.
					newCompDt = DataTypeUtilities.getBaseDataType(newCompDt);
					oldCompDt = DataTypeUtilities.getBaseDataType(oldCompDt);
				}

				if (areSameClassType(newCompDt, oldCompDt) && isAnonymousType(oldCompDt)) {
					// Got a match so set the ID.
					transformDataType(newCompDt, newFileArchive, oldCompDt);

					// Now process children anonymous data types for anonymous composites.
					processAnonymous(oldCompDt, newCompDt, oldFileArchive, newFileArchive);
				}
			}
		}
	}

	private static void transformInnerAnonymousDataType(DataType oldDataType, DataType newDataType,
			FileDataTypeManager oldFileArchive, FileDataTypeManager newFileArchive) {

		boolean isOldAnonymous = isAnonymousType(oldDataType);
		boolean isNewAnonymous = isAnonymousType(newDataType);
		if (isOldAnonymous && isNewAnonymous && areSameClassType(newDataType, oldDataType)) {
			// Got a match on the anonymous data type, so set the ID.
			transformDataType(newDataType, newFileArchive, oldDataType);
		}

		// Now process children anonymous data types for anonymous composites.
		processAnonymous(oldDataType, newDataType, oldFileArchive, newFileArchive);
	}

	private static DataTypeComponent getAnonymousMatch(Composite oldComposite,
			Composite newComposite, DataTypeComponent newComponent) {

		String newFieldName = newComponent.getFieldName();
		if (newFieldName != null && !newFieldName.isEmpty()) {
			// Match by field name
			return getNamedComponent(oldComposite, newFieldName);
		}
		if (oldComposite.getNumComponents() == newComposite.getNumComponents()) {
			// Match by ordinal
			int ordinal = newComponent.getOrdinal();
			return oldComposite.getComponent(ordinal);
		}
		return null;
	}

	private static int getAnonymousPointerDepth(DataType newComponentDt) {
		int depth = 0;
		DataType currentDt = newComponentDt;
		while (currentDt instanceof Pointer) {
			Pointer pointer = (Pointer) currentDt;
			currentDt = pointer.getDataType();
			depth++;
		}
		if (isAnonymousType(currentDt)) {
			return depth;
		}
		return 0;
	}

	private static int getAnonymousArrayElementCount(DataType newCompDt) {
		int elementCount = 0;
		DataType currentDt = newCompDt;
		while (currentDt instanceof Array) {
			Array array = (Array) currentDt;
			currentDt = array.getDataType();
			if (elementCount == 0) {
				elementCount = 1;
			}
			elementCount *= array.getNumElements();
		}
		if (isAnonymousType(currentDt)) {
			return elementCount;
		}
		return 0;
	}

	private static int getAnonymousTypeDefDepth(DataType newCompDt) {
		int depth = 0;
		DataType currentDt = newCompDt;
		while (currentDt instanceof TypeDef) {
			TypeDef typeDef = (TypeDef) currentDt;
			currentDt = typeDef.getDataType();
			depth++;
		}
		if (isAnonymousType(currentDt)) {
			return depth;
		}
		return 0;
	}

	private static DataTypeComponent getNamedComponent(Composite composite, String fieldName) {
		for (DataTypeComponent dataTypeComponent : composite.getDefinedComponents()) {
			if (fieldName.equals(dataTypeComponent.getFieldName())) {
				return dataTypeComponent; // found match so return it.
			}
		}
		return null; // No match.
	}

	private static DataType transformDataType(DataType newDataType,
			FileDataTypeManager oldFileArchive, FileDataTypeManager newFileArchive) {

		DataType matchingDataType =
			getMatchingDataType(newDataType, oldFileArchive, newFileArchive);
		transformDataType(newDataType, newFileArchive, matchingDataType);
		return matchingDataType;
	}

	private static void transformDataType(DataType newDataType, FileDataTypeManager newFileArchive,
			DataType matchingDataType) {

		// If we got a data type with the same name that is the same kind of data type then transform it.
		// Give the newDataType the same ID as the matchingDataType.
		if (matchingDataType != null && (newDataType.getClass() == matchingDataType.getClass())) {
			SourceArchive oldSourceArchive = matchingDataType.getSourceArchive();
			UniversalID oldUniversalID = matchingDataType.getUniversalID();
			SourceArchive newSourceArchive = newDataType.getSourceArchive();
			UniversalID newUniversalID = newDataType.getUniversalID();
			boolean isNewSourceArchiveLocal = isLocalSourceArchive(newDataType);
			if (oldSourceArchive != null) {
				boolean isOldSourceArchiveLocal = isLocalSourceArchive(matchingDataType);
				UniversalID oldSourceArchiveID = oldSourceArchive.getSourceArchiveID();
				UniversalID newSourceArchiveID = newSourceArchive.getSourceArchiveID();
				// Is this a local data type?
				if (isOldSourceArchiveLocal) {
					if (!isNewSourceArchiveLocal) {
						SourceArchive localSourceArchive = getLocalSourceArchive(newDataType);
						if (dataTypeIDExists(newFileArchive, newDataType, localSourceArchive,
							oldUniversalID)) {
							return; // Already have data type with this ID.
						}
						newDataType.setSourceArchive(localSourceArchive);
					}
				}
				// Is this a built-in data type?
				else if (DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID.equals(oldSourceArchiveID)) {
					if (!DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID.equals(newSourceArchiveID)) {
						Msg.warn(DataTypeArchiveTransformer.class,
							"DataType " + newDataType.getName() + " has source of " +
								newSourceArchive.getName() + " when old data type was BUILT-IN.");
					}
				}
				else if (DataTypeManager.BUILT_IN_ARCHIVE_UNIVERSAL_ID.equals(newSourceArchiveID)) {
					// don't set source on built-ins
				}
				else if (newUniversalID == null) {
					Msg.error(DataTypeArchiveTransformer.class,
						"Error: " + newDataType.getPathName() + " doesn't have a Universal ID.");
				}
				else if (!newUniversalID.equals(oldUniversalID) || !isNewSourceArchiveLocal) {
					SourceArchive resolvedSourceArchive =
						newFileArchive.resolveSourceArchive(oldSourceArchive);
					if (dataTypeIDExists(newFileArchive, newDataType, resolvedSourceArchive,
						oldUniversalID)) {
						return; // Already have data type with this ID.
					}
					newDataType.setSourceArchive(oldSourceArchive);
				}
			}
			else {
				// Doesn't have source archive, so let it be whatever it is.
			}
			if (!(newDataType instanceof BuiltIn) && oldUniversalID != null) {
				if (!oldUniversalID.equals(newUniversalID)) {
					((DataTypeDB) newDataType).setUniversalID(oldUniversalID);
				}
			}
		}
	}

	private static boolean dataTypeIDExists(FileDataTypeManager newFileArchive,
			DataType newDataType, SourceArchive newSourceArchive, UniversalID oldUniversalID) {
		if (oldUniversalID != null) {
			return false;
		}
		DataType existingDataType = newFileArchive.getDataType(newSourceArchive, oldUniversalID);
		if (existingDataType != null) {
			// Oh no! Can't use the expected ID because a data type already exists with it.
			// So just return without doing anything.
			Msg.warn(DataTypeArchiveTransformer.class,
				"Can't transform dataType \"" + newDataType.getPathName() + "\"\n" +
					"since dataType \"" + existingDataType.getPathName() + "\" already exists\n" +
					"with old ID of " + oldUniversalID + ".");
			return true;
		}
		return false;
	}

	private static DataType getMatchingDataType(DataType newDataType,
			FileDataTypeManager oldFileArchive, FileDataTypeManager newFileArchive) {

		// Try to get data type with same full path name.
		DataType oldDataType =
			oldFileArchive.getDataType(newDataType.getCategoryPath(), newDataType.getName());
		if (oldDataType != null) {
			return oldDataType;
		}
		// Get all the old data types with the same name.
		ArrayList<DataType> oldDataTypeList = new ArrayList<>();
		oldFileArchive.findDataTypes(newDataType.getName(), oldDataTypeList);
		if (oldDataTypeList.isEmpty()) {
			return null;
		}
		// Get all new data types with the same name.
		ArrayList<DataType> newDataTypeList = new ArrayList<>();
		newFileArchive.findDataTypes(newDataType.getName(), newDataTypeList);
		// If there is a one to one match then assume a match.
		if (oldDataTypeList.size() == 1 && newDataTypeList.size() == 1) {
			DataType oldArchiveDataType = oldDataTypeList.get(0);
			if (areSameClassType(newDataType, oldArchiveDataType)) {
				return oldArchiveDataType;
			}
		}
		// Otherwise see if there is a single match based on full path name ignoring case.
		String newPath = newDataType.getCategoryPath().getPath().toLowerCase();
		DataType ignoreCaseDataType = null;
		for (DataType oldArchiveDataType : oldDataTypeList) {
			String oldPath = oldArchiveDataType.getCategoryPath().getPath().toLowerCase();
			if (oldPath.equals(newPath)) {
				if (ignoreCaseDataType == null) {
					ignoreCaseDataType = oldArchiveDataType;
				}
				else {
					// Found more than one that matches so give up.
					return null;
				}
			}
		}
		// If we got only one old then see if 1 to 1 match with only one new.
		if (ignoreCaseDataType != null) {
			int countNewWithoutCase = 0;
			for (DataType newArchiveDataType : newDataTypeList) {
				String otherNewPath = newArchiveDataType.getCategoryPath().getPath().toLowerCase();
				if (otherNewPath.equals(newPath)) {
					countNewWithoutCase++;
				}
			}
			if (countNewWithoutCase == 1 && areSameClassType(newDataType, ignoreCaseDataType)) {
				return ignoreCaseDataType; // 1 to 1 match when case insensitive.
			}
		}
		return null;
	}

	private static boolean areSameClassType(DataType dataType1, DataType dataType2) {
		if (dataType1 == null || dataType2 == null) {
			return false;
		}
		return dataType1.getClass() == dataType2.getClass();
	}

	private static boolean isAnonymousType(DataType newDataType) {
		String name = newDataType.getName();
		if (newDataType instanceof Structure && hasAnonymousName(name, "_struct_")) {
			return true;
		}
		if (newDataType instanceof Union && name.startsWith("_union_")) {
			return true;
		}
		if (newDataType instanceof Enum && name.startsWith("enum_")) {
			return true;
		}
		return false;
	}

	/**
	 * Checks to see if the indicated name is an anonymous name with the indicated prefix
	 * followed by a number.
	 * @param name the anonymous data type name to check.
	 * @param prefix the prefix string ("_struct_", "_union_", "enum_").
	 * @return true if the name is an anonymous data type name with the expected prefix.
	 */
	private static boolean hasAnonymousName(String name, String prefix) {
		if (!name.startsWith(prefix)) {
			return false; // doesn't have expected prefix.
		}
		String suffix = name.substring(prefix.length());
		if (!StringUtils.isNumeric(suffix)) {
			return false;
		}
		return true;
	}

	private static SourceArchive getLocalSourceArchive(DataType dataType) {
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		return dataTypeManager.getLocalSourceArchive();
	}

	private static void fixEachDataTypeTimestamp(FileDataTypeManager oldFileArchive,
			FileDataTypeManager newFileArchive, TaskMonitor monitor) throws CancelledException {
		boolean commit = false;
		int transactionID = newFileArchive.startTransaction("Fixing Data Type Archive Timestamps");
		try {
			Iterator<DataType> allDataTypes = newFileArchive.getAllDataTypes();
			while (allDataTypes.hasNext()) {
				monitor.checkCanceled();
				DataType newDataType = allDataTypes.next();
				fixDataTypeTimestamp(newDataType, oldFileArchive, newFileArchive);
//				monitor.incrementProgress(1);
				monitor.setMessage("Fixing timestamp for " + newDataType.getPathName());
			}
			commit = true;
		}
		finally {
			newFileArchive.endTransaction(transactionID, commit);
		}
	}

	private static void fixDataTypeTimestamp(DataType newDataType,
			FileDataTypeManager oldFileArchive, FileDataTypeManager newFileArchive) {
		UniversalID universalID = newDataType.getUniversalID();
		SourceArchive sourceArchive = newDataType.getSourceArchive();
		if (sourceArchive == newFileArchive.getLocalSourceArchive()) {
			// Use the the old file archive as the source archive since local.
			sourceArchive = oldFileArchive.getLocalSourceArchive();
		}
		DataType oldDataType;
		if (universalID != null) {
			oldDataType = oldFileArchive.getDataType(sourceArchive, universalID);
		}
		else {
			oldDataType =
				oldFileArchive.getDataType(newDataType.getCategoryPath(), newDataType.getName());
		}
		if (oldDataType != null) {
			// Check to see if the data type is unchanged.
			if (oldDataType.equals(newDataType)) {
				// Change the timestamp to the old timestamp.
				long oldLastChangeTime = oldDataType.getLastChangeTime();
				newDataType.setLastChangeTime(oldLastChangeTime);
			}
		}
	}

	private static boolean isLocalSourceArchive(DataType sameNamedDataType) {
		DataTypeManager dataTypeManager = sameNamedDataType.getDataTypeManager();
		SourceArchive sourceArchive = sameNamedDataType.getSourceArchive();
		UniversalID sourceArchiveID = sourceArchive.getSourceArchiveID();
		UniversalID universalID = dataTypeManager.getUniversalID();
		return sourceArchiveID == universalID;
	}

	private static void saveNewArchive(FileDataTypeManager oldFileArchive,
			FileDataTypeManager newFileArchive, File destinationFile)
			throws DuplicateFileException, IOException {
		UniversalID oldUniversalID = oldFileArchive.getUniversalID();
		newFileArchive.saveAs(destinationFile, oldUniversalID);
		Msg.info(DataTypeArchiveTransformer.class,
			"Resulting file ID = " + newFileArchive.dbHandle.getDatabaseId());
	}

	private static void saveNewArchive(FileDataTypeManager newFileArchive, File destinationFile)
			throws DuplicateFileException, IOException {
		newFileArchive.saveAs(destinationFile);

		FileDataTypeManager destinationFileArchive =
			FileDataTypeManager.openFileArchive(destinationFile, false);
		if (destinationFileArchive != null) {
			UniversalID destinationUniversalID = destinationFileArchive.getUniversalID();
			destinationFileArchive.close();
			Msg.info(DataTypeArchiveTransformer.class,
				"Resulting file ID = " + destinationUniversalID.getValue());
		}
	}

	static File myOldFile = null;
	static File myNewFile = null;
	static File myDestinationFile = null;

	@Override
	public void launch(GhidraApplicationLayout layout, String[] args) {
		ApplicationConfiguration appConfig = new DockingApplicationConfiguration();
		Application.initializeApplication(layout, appConfig);
		// Perform Class searching so we load data type classes that may have moved or
		// changed name. This is needed to map a data type's old path name to the new one.
		performClassSearching(appConfig.getTaskMonitor());

		fixupGUI();

		UniversalIdGenerator.initialize();
		final JFrame frame = new JFrame("Transform Data Type Archive");
		frame.setLayout(new GridBagLayout());
		final DataTypeArchiveTransformerPanel filePanel = new DataTypeArchiveTransformerPanel();
		final JPanel statusPanel = new JPanel(new BorderLayout());
		final JButton transformButton = new JButton("Transform");
		final JButton exitButton = new JButton("Exit");

		final RunManager runManager = new RunManager();
		JComponent monitorComponent = runManager.getMonitorComponent();
		runManager.showCancelButton(true);

		// Add the file panel.
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(2, 2, 2, 2);
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.gridwidth = 2;
		filePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		frame.add(filePanel, gbc);

		// Add the taskMonitor to the status area.
		Dimension monitorSize = monitorComponent.getPreferredSize();
		monitorSize.width = filePanel.getPreferredSize().width;
		monitorComponent.setPreferredSize(monitorSize);
		monitorComponent.setVisible(true);
		statusPanel.add(monitorComponent, BorderLayout.EAST);
		// Add the status message to the status area.
		JLabel statusLabel = new GDLabel("    ");
		statusPanel.add(statusLabel, BorderLayout.CENTER);
		Dimension preferredSize = statusLabel.getPreferredSize();
		preferredSize.height = monitorComponent.getPreferredSize().height;
		statusLabel.setPreferredSize(preferredSize);
		statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
		// Add the status area.
		gbc.gridx = 0;
		gbc.gridy = 2;
		gbc.gridwidth = 2;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		frame.add(statusPanel, gbc);
		gbc.fill = GridBagConstraints.NONE;

		// Add the buttons.
		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.gridwidth = 1;
		gbc.weightx = 1;
		transformButton.addActionListener(e -> {

			MonitoredRunnable r = monitor -> {
				try {
					transformButton.setEnabled(false);
					exitButton.setEnabled(false);
					String inProgressMessage = "";
					statusLabel.setText(inProgressMessage);
					statusLabel.setToolTipText(inProgressMessage);
					filePanel.transform(monitor);
					File destinationFile = filePanel.getDestinationFile();
					statusLabel.setForeground(Color.blue);
					String message = "Transformation successfully created " +
						destinationFile.getAbsolutePath() + ".";
					statusLabel.setText(message);
					statusLabel.setToolTipText(message);
				}
				catch (CancelledException cancelExc) {
					String cancelMessage = "User canceled transformation.";
					statusLabel.setText(cancelMessage);
					statusLabel.setToolTipText(cancelMessage);
				}
				catch (Exception exc) {
					statusLabel.setForeground(Color.red);
					statusLabel.setText(exc.getMessage());
					statusLabel.setToolTipText(exc.getMessage());
					exc.printStackTrace();
				}
				finally {
					transformButton.setEnabled(true);
					exitButton.setEnabled(true);
				}
			};
			runManager.runNow(r, "", 250);
		});
		frame.add(transformButton, gbc);

		gbc.gridx = 1;
		gbc.gridy = 1;
		gbc.gridwidth = 1;
		gbc.weightx = 1;
		exitButton.addActionListener(e -> {
			frame.setVisible(false);
			System.exit(0);
		});
		frame.add(exitButton, gbc);

		frame.addWindowListener(new WindowAdapter() {

			@Override
			public void windowClosing(WindowEvent e) {
				super.windowClosing(e);
				System.exit(0);
			}

		});

		frame.pack();
		monitorComponent.setVisible(false);
		frame.setVisible(true);
	}

	private void performClassSearching(TaskMonitor monitor) {

		// The class searcher searches the classpath, and Ghidra's classpath should be complete
		// for this configuration at this point.
		try {
			ClassSearcher.search(monitor);
		}
		catch (CancelledException e) {
			Msg.debug(this, "Class searching unexpectedly cancelled.");
		}
	}

	public static void fixupGUI() {
		// Make the test look & feel as it would normally.
		SystemUtilities.runSwingNow(() -> {
			try {
				UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
			}
			catch (Exception e1) {
				Msg.debug(DataTypeArchiveTransformer.class,
					"Unable to install the system Look and Feel");
			}
		});

		// Fix up the default fonts that Java 1.5.0 changed to Courier, which looked terrible.
		Font f = new Font("Monospaced", Font.PLAIN, 12);
		UIManager.put("PasswordField.font", f);
		UIManager.put("TextArea.font", f);
	}

}
