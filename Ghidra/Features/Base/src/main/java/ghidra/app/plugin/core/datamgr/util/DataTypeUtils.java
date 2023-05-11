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
package ghidra.app.plugin.core.datamgr.util;

import java.awt.*;
import java.util.*;
import java.util.List;

import javax.swing.Icon;

import generic.theme.GColor;
import generic.theme.GIcon;
import ghidra.app.services.DataTypeQueryService;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import resources.MultiIcon;
import resources.ResourceManager;

public class DataTypeUtils {
	private static final Comparator<Object> DATA_TYPE_LOOKUP_COMPARATOR =
		new CaseInsensitveDataTypeLookupComparator();
	private static final char END_CHAR = '\uffff';
	private static final char BEGIN_CHAR = '\u0000';

	private static final Color COLOR_ICON_HIGHLIGHT =
		new GColor("color.bg.plugin.datamgr.icon.highlight");

	private static Map<Icon, MultiIcon> highlightIconMap = new HashMap<>();

	private static Icon defaultIcon;
	private static Icon disabledIcon;
	private static Icon favoriteIcon;
	private static Icon disabledFavoriteIcon;
	private static Icon builtInIcon;
	private static Icon disabledBuiltInIcon;
	private static Icon rootIcon;
	private static Icon openRootIcon;
	private static Icon openFolderIcon;
	private static Icon disabledOpenFolderIcon;
	private static Icon closedFolderIcon;
	private static Icon disabledClosedFolderIcon;
	private static Icon lockedOpenFolderIcon;
	private static Icon lockedClosedFolderIcon;
	private static Icon openArchiveFolderIcon;
	private static Icon closedArchiveFolderIcon;

	private static DataTypeIconWrapper[] dataTypeIconWrappers;
	private static boolean imagesLoaded;

	private DataTypeUtils() {
		// utils class
	}

	private static void loadImages() {
		if (imagesLoaded) {
			return;
		}
		imagesLoaded = true;
		defaultIcon = new GIcon("icon.plugin.datatypes.default");
		disabledIcon = new GIcon("icon.plugin.datatypes.default.disabled");

		favoriteIcon = new GIcon("icon.plugin.datatypes.util.favorite");
		disabledFavoriteIcon = new GIcon("icon.plugin.datatypes.util.favorite.disabled");

		builtInIcon = new GIcon("icon.plugin.datatypes.built.in");
		disabledBuiltInIcon = new GIcon("icon.plugin.datatypes.built.in.disabled");

		rootIcon = new GIcon("icon.plugin.datatypes.util.root");
		openRootIcon = new GIcon("icon.plugin.datatypes.util.open.root");

		openFolderIcon = new GIcon("icon.plugin.datatypes.util.open.folder");
		disabledOpenFolderIcon = new GIcon("icon.plugin.datatypes.util.open.folder.disabled");

		closedFolderIcon = new GIcon("icon.plugin.datatypes.util.closed.folder");
		disabledClosedFolderIcon = new GIcon("icon.plugin.datatypes.util.closed.folder.disabled");

		lockedOpenFolderIcon = new GIcon("icon.plugin.datatypes.util.open.folder.locked");
		lockedClosedFolderIcon = new GIcon("icon.plugin.datatypes.util.closed.folder.locked");

		openArchiveFolderIcon = new GIcon("icon.plugin.datatypes.util.open.archive");
		closedArchiveFolderIcon = new GIcon("icon.plugin.datatypes.util.closed.archive");

		createDataTypeIcons();

	}

	private static void createDataTypeIcons() {
		List<DataTypeIconWrapper> list = new ArrayList<>();

		Icon enumIcon = new GIcon("icon.plugin.datatypes.enum");
		list.add(new DataTypeIconWrapper(Enum.class, enumIcon,
			ResourceManager.getDisabledIcon(enumIcon)));

		Icon functionIcon = new GIcon("icon.plugin.datatypes.function");
		list.add(new DataTypeIconWrapper(FunctionDefinition.class, functionIcon,
			ResourceManager.getDisabledIcon(functionIcon)));

		Icon pointerIcon = new GIcon("icon.plugin.datatypes.pointer");
		list.add(new DataTypeIconWrapper(Pointer.class, pointerIcon,
			ResourceManager.getDisabledIcon(pointerIcon)));

		Icon typedefIcon = new GIcon("icon.plugin.datatypes.typedef");
		list.add(new DataTypeIconWrapper(TypeDef.class, typedefIcon,
			ResourceManager.getDisabledIcon(typedefIcon)));

		Icon unionIcon = new GIcon("icon.plugin.datatypes.union");
		list.add(new DataTypeIconWrapper(Union.class, unionIcon,
			ResourceManager.getDisabledIcon(unionIcon)));

		Icon structureIcon = new GIcon("icon.plugin.datatypes.structure");
		list.add(new DataTypeIconWrapper(Structure.class, structureIcon,
			ResourceManager.getDisabledIcon(structureIcon)));

		dataTypeIconWrappers = list.toArray(new DataTypeIconWrapper[list.size()]);
	}

	/**
	 * Returns the root folder icon.
	 * @param expanded true to use the expanded icon; false to use the collapsed icon.
	 * @return the root folder icon.
	 */
	public static Icon getRootIcon(boolean expanded) {
		loadImages();
		return expanded ? openRootIcon : rootIcon;
	}

	/**
	 * Returns the open folder icon.
	 *
	 * @param disabled True returns a disabled icon; false returns the normal icon.
	 * @return the open folder icon.
	 */
	public static Icon getOpenFolderIcon(boolean disabled) {
		loadImages();
		if (disabled) {
			return disabledOpenFolderIcon;
		}

		return openFolderIcon;
	}

	/**
	 * Returns the closed folder icon.
	 *
	 * @param disabled True returns a disabled icon; false returns the normal icon.
	 * @return the closed folder icon.
	 */
	public static Icon getClosedFolderIcon(boolean disabled) {
		loadImages();
		if (disabled) {
			return disabledClosedFolderIcon;
		}

		return closedFolderIcon;
	}

	/**
	 * Returns the open archive folder icon.
	 *
	 * @param isLocked True means to return the checked-out open archive folder icon
	 * @return the open archive folder icon.
	 */
	public static Icon getOpenArchiveFolder(boolean isLocked) {
		loadImages();
		if (isLocked) {
			return lockedOpenFolderIcon;
		}

		return openArchiveFolderIcon;
	}

	/**
	 * Returns the closed folder icon.
	 *
	 * @param isLocked True means to return the checked-out closed folder icon
	 * @return the closed folder icon.
	 */
	public static Icon getClosedArchiveFolder(boolean isLocked) {
		loadImages();
		if (isLocked) {
			return lockedClosedFolderIcon;
		}

		return closedArchiveFolderIcon;
	}

	/**
	 * Returns the BuiltIn icon.
	 *
	 * @param disabled True returns a disabled icon; false returns the normal icon.
	 * @return the BuiltIn icon.
	 */
	public static Icon getBuiltInIcon(boolean disabled) {
		loadImages();
		if (disabled) {
			return disabledBuiltInIcon;
		}

		return builtInIcon;
	}

	/**
	 * Returns the favorites icon.
	 *
	 * @param disabled True returns a disabled icon; false returns the normal icon.
	 * @return the favorites icon.
	 */
	public static Icon getFavoriteIcon(boolean disabled) {
		loadImages();
		if (disabled) {
			return disabledFavoriteIcon;
		}

		return favoriteIcon;
	}

	/**
	 * Finds the icon associated with the provided data type.
	 *
	 * @param dataType The data type for which to find an icon.
	 * @param disabled True returns a disabled icon; false returns the normal icon.
	 * @return the icon associated with the provided data type.
	 */
	public static Icon getIconForDataType(DataType dataType, boolean disabled) {
		loadImages();

		for (DataTypeIconWrapper element : dataTypeIconWrappers) {
			Icon icon = element.getIcon(dataType, disabled);
			if (icon != null) {
				return icon;
			}
		}

		if (disabled) {
			return disabledIcon;
		}
		return defaultIcon;
	}

	/**
	 * Returns an icon that adds highlighting to the provided icon.
	 *
	 * @param baseIcon The icon to highlight.
	 * @return the highlighted icon.
	 */
	public static Icon getHighlightIcon(Icon baseIcon) {
		loadImages();
		MultiIcon highlightIcon = highlightIconMap.get(baseIcon);

		if (highlightIcon == null) {
			highlightIcon = new MultiIcon(new HighlightIcon(COLOR_ICON_HIGHLIGHT));
			highlightIcon.addIcon(baseIcon);
			highlightIconMap.put(baseIcon, highlightIcon);
		}

		return highlightIcon;
	}

	/**
	 * Returns a sorted list of {@link DataType}s that have names which start with the given search
	 * string.   The list is sorted according to {@link #DATA_TYPE_LOOKUP_COMPARATOR}.
	 *
	 * @param searchString The name of the DataTypes to match.
	 * @param dataService The service from which the data types will be taken.
	 * @return A sorted list of {@link DataType}s that have names which start with the given search
	 *         string.
	 */
	public static List<DataType> getStartsWithMatchingDataTypes(String searchString,
			DataTypeQueryService dataService) {
		return getMatchingSubList(searchString, searchString + END_CHAR,
			dataService.getSortedDataTypeList());
	}

	/**
	 * Returns a sorted list of {@link DataType}s that have names which match the given search
	 * string.  The list is sorted according to {@link #DATA_TYPE_LOOKUP_COMPARATOR}.
	 *
	 * @param searchString The name of the DataTypes to match.
	 * @param dataService The service from which the data types will be taken.
	 * @return A sorted list of {@link DataType}s that have names which match the given search
	 *         string.
	 */
	public static List<DataType> getExactMatchingDataTypes(String searchString,
			DataTypeQueryService dataService) {
		return getMatchingSubList(searchString, searchString + BEGIN_CHAR,
			dataService.getSortedDataTypeList());
	}

	/**
	 * Changes the given text to prepare it for use in searching for data types.  Clients should
	 * call this method to make sure that the given text is suitable for use when searching the
	 * data type values returned by
	 * {@link #getExactMatchingDataTypes(String, DataTypeQueryService)} and
	 * {@link #getStartsWithMatchingDataTypes(String, DataTypeQueryService)}.
	 * @param searchText the search text
	 * @return the updated text
	 */
	public static String prepareSearchText(String searchText) {
		return searchText.replaceAll(" ", "");
	}

	/*testing*/ static List<DataType> getMatchingSubList(String searchTextStart,
			String searchTextEnd, List<DataType> dataTypeList) {

		searchTextStart = prepareSearchText(searchTextStart);
		searchTextEnd = prepareSearchText(searchTextEnd);

		int startIndex = binarySearchWithDuplicates(dataTypeList, searchTextStart,
			DATA_TYPE_LOOKUP_COMPARATOR);

		int endIndex = binarySearchWithDuplicates(dataTypeList, searchTextEnd,
			DATA_TYPE_LOOKUP_COMPARATOR);

		return dataTypeList.subList(startIndex, endIndex);
	}

	/**
	 * Get the base data type for the specified data type.
	 *
	 * <p>For example, the base data type for Word*[5] is Word.  For a pointer, the base data type
	 * is the type being pointed to or the pointer itself if it is pointing at nothing.
	 *
	 * <p>If "INT" is a typedef on a "dword" then INT[7][3] would have a base data type of dword.
	 * If you wanted to get the INT from INT[7][3] you should call getNamedBasedDataType(DataType)
	 * instead.
	 *
	 * @param dt the data type whose base data type is to be determined.
	 * @return the base data type.
	 */
	public static DataType getBaseDataType(DataType dt) {
		DataType baseDataType = dt;
		while ((baseDataType instanceof Pointer) || (baseDataType instanceof Array) ||
			(baseDataType instanceof TypeDef)) {
			if (baseDataType instanceof Pointer) {
				DataType innerDt = ((Pointer) baseDataType).getDataType();
				if (innerDt != null) {
					baseDataType = innerDt;
				}
				else {
					return baseDataType;
				}
			}
			else if (baseDataType instanceof Array) {
				baseDataType = ((Array) baseDataType).getDataType();
			}
			else {
				baseDataType = ((TypeDef) baseDataType).getDataType();
			}
		}
		return baseDataType;
	}

	/**
	 * Get the named base data type for the specified data type.  This method intentionally does
	 * not drill down into typedefs.
	 *
	 * <p>For example, the named base data type for Word*[5] is Word.  For a pointer, the named
	 * base data type is the type being pointed to or the pointer itself if it is pointing at
	 * nothing.
	 *
	 * <p>If "INT" is a typedef on a "dword", then INT[7][3] would have a named base data type of
	 * INT.  If you wanted to get the dword from INT[7][3] you should call
	 * getBasedDataType(DataType) instead.
	 *
	 * @param dt the data type whose named base data type is to be determined.
	 * @return the base data type.
	 */
	public static DataType getNamedBaseDataType(DataType dt) {
		DataType baseDataType = dt;
		while ((baseDataType instanceof Pointer) || (baseDataType instanceof Array)) {
			if (baseDataType instanceof Pointer) {
				DataType innerDt = ((Pointer) baseDataType).getDataType();
				if (innerDt != null) {
					baseDataType = innerDt;
				}
				else {
					return baseDataType;
				}
			}
			else if (baseDataType instanceof Array) {
				baseDataType = ((Array) baseDataType).getDataType();
			}
		}
		return baseDataType;
	}

	/**
	 * Create a copy of the chain of data types that eventually lead to a named
	 * data type.
	 * <p>
	 * Returns a {@link DataType#copy(DataTypeManager) copy()} of the first named data type found
	 * in the pointer / array type chain, and returns an identical chain of pointer / arrays up to
	 * the copied named type.
	 *
	 * @param dataType data type to be copied
	 * @param dtm data type manager
	 * @return deep copy of dataType
	 */
	public static DataType copyToNamedBaseDataType(DataType dataType, DataTypeManager dtm) {
		if (dataType instanceof Pointer) {
			Pointer pdt = (Pointer) dataType;
			return new PointerDataType(copyToNamedBaseDataType(pdt.getDataType(), dtm),
				pdt.hasLanguageDependantLength() ? -1 : pdt.getLength(), dtm);
		}
		else if (dataType instanceof Array) {
			Array adt = (Array) dataType;
			return new ArrayDataType(copyToNamedBaseDataType(adt.getDataType(), dtm),
				adt.getNumElements(), adt.getElementLength(), dtm);
		}
		else {
			return dataType.copy(dtm);
		}
	}

	public static void showUnmodifiableArchiveErrorMessage(Component parent, String title,
			DataTypeManager dtm) {
		String msg;
		if (dtm instanceof ProgramBasedDataTypeManager) {
			msg = "The Program is not modifiable!\n";
		}
		else if (dtm instanceof FileArchiveBasedDataTypeManager) {
			msg = "The archive file is not modifiable!\nYou must open the archive for editing\n" +
				"before performing this operation.\n" + dtm.getName();
		}
		else if (dtm instanceof ProjectArchiveBasedDataTypeManager) {
			ProjectArchiveBasedDataTypeManager projectDtm =
				(ProjectArchiveBasedDataTypeManager) dtm;
			if (!projectDtm.isUpdatable() && !projectDtm.getDomainFile().canCheckout()) {
				msg = "The project archive is not modifiable!\n" + dtm.getName();
			}
			else {
				msg = "The project archive is not modifiable!\nYou must check out the archive\n" +
					"before performing this operation.\n" + dtm.getName();
			}
		}
		else {
			msg = "The Archive is not modifiable!\n";
		}
		Msg.showInfo(DataTypeUtils.class, parent, title, msg);
	}

	public static int binarySearchWithDuplicates(List<DataType> data,
			String searchItem, Comparator<Object> comparator) {
		int index = Collections.binarySearch(data, searchItem, comparator);

		// the binary search returns a negative, incremented position if there is no match in the
		// list for the given search
		if (index < 0) {
			index = -index - 1;
		}
		else {
			index = findTrueStartIndex(searchItem, data, index, comparator);
		}
		return index;
	}

	// finds the index of the first element in the given list--this is used in conjunction with
	// the binary search, which doesn't produce the desired results when searching lists with 
	// duplicates

	private static int findTrueStartIndex(String searchItem, List<DataType> dataList,
			int startIndex, Comparator<Object> comparator) {
		if (startIndex < 0) {
			return startIndex;
		}

		for (int i = startIndex; i >= 0; i--) {
			if (comparator.compare(dataList.get(i), searchItem) != 0) {
				return ++i; // previous index
			}
		}

		return 0; // this means that the search text matches the first element in the lists
	}

}

//==================================================================================================
// Inner Classes
//==================================================================================================

class DataTypeIconWrapper {
	private Icon defaultIcon;
	private Icon disabledIcon;
	private Class<? extends DataType> dataTypeClass;

	DataTypeIconWrapper(Class<? extends DataType> dataTypeClass, Icon defaultIcon,
			Icon disabledIcon) {
		this.dataTypeClass = dataTypeClass;
		this.defaultIcon = defaultIcon;
		this.disabledIcon = disabledIcon;
	}

	Icon getIcon(DataType dataType, boolean disabled) {
		if (dataTypeClass.isInstance(dataType)) {
			if (disabled) {
				return disabledIcon;
			}
			return defaultIcon;
		}

		return null;
	}
}

class CaseInsensitveDataTypeLookupComparator implements Comparator<Object> {
	@Override
	public int compare(Object o1, Object o2) {
		if (o1 instanceof DataType && o2 instanceof String) {
			DataType dt1 = (DataType) o1;
			String name1 = dt1.getName();
			name1 = name1.replaceAll(" ", "");
			return name1.compareToIgnoreCase(((String) o2));
		}

		throw new AssertException("Comparator used in an unexpected way--it is " +
			"intended to be used to lookup a String key in a list of DataType objects");
	}
}

class HighlightIcon implements Icon {
	private Color color;
	private static final int WIDTH = 16;
	private static final int HEIGHT = 16;

	HighlightIcon(Color color) {
		this.color = color;
	}

	@Override
	public int getIconHeight() {
		return HEIGHT;
	}

	@Override
	public int getIconWidth() {
		return WIDTH;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		g.setColor(color);
		g.fillRect(x + 1, y, WIDTH, HEIGHT);
		g.drawRect(x, y, WIDTH + 1, HEIGHT - 1);
	}
}
