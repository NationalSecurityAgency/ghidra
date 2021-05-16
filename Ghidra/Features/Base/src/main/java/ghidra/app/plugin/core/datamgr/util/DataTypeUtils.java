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
import javax.swing.ImageIcon;

import ghidra.app.services.DataTypeQueryService;
import ghidra.app.services.DataTypeManagerService;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.Msg;
import ghidra.util.datastruct.Algorithms;
import ghidra.util.exception.AssertException;
import resources.MultiIcon;
import resources.ResourceManager;

public class DataTypeUtils {
	private static final Comparator<Object> DATA_TYPE_LOOKUP_COMPARATOR =
		new CaseInsensitveDataTypeLookupComparator();
	private static final char END_CHAR = '\uffff';
	private static final char BEGIN_CHAR = '\u0000';

	private static Map<Icon, MultiIcon> highlightIconMap = new HashMap<>();

	private static String OPEN_FOLDER = "images/openFolder.png";
	private static String CLOSED_FOLDER = "images/closedFolder.png";
	private static String DISABLED_OPEN_FOLDER = "images/disabledOpenFolder.png";
	private static String DISABLED_CLOSED_FOLDER = "images/disabledClosedFolder.png";
	private static String DEFAULT_ICON = "images/defaultDt.gif";
	private static String DISABLED_DEFAULT_ICON = "images/disabledCode.gif";
	private static String LOCKED_OPEN_FOLDER = "images/openFolderCheckedOut.png";
	private static String LOCKED_CLOSED_FOLDER = "images/closedFolderCheckedOut.png";
	private static String OPEN_ARCHIVE_FOLDER = "images/openFolderArchive.png";
	private static String CLOSED_ARCHIVE_FOLDER = "images/closedFolderArchive.png";
	private static String ROOT_ICON = "images/BookShelf.png";
	private static String OPEN_ROOT_ICON = "images/BookShelfOpen.png";
	private static String FAVORITE_ICON = "images/emblem-favorite.png";
	private static String BUILT_IN_ICON = "images/package_development.png";
	private static String STRUCTURE_ICON = "images/cstruct.png";
	private static String UNION_ICON = "images/cUnion.png";
	private static String TYPEDEF_ICON = "images/typedef.png";
	private static String FUNCTION_ICON = "images/functionDef.png";
	private static String ENUM_ICON = "images/enum.png";
	private static String POINTER_ICON = "images/fingerPointer.png";

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
		defaultIcon = ResourceManager.loadImage(DEFAULT_ICON);
		disabledIcon = ResourceManager.loadImage(DISABLED_DEFAULT_ICON);

		favoriteIcon = ResourceManager.loadImage(FAVORITE_ICON);
		disabledFavoriteIcon = ResourceManager.getDisabledIcon((ImageIcon) favoriteIcon);

		builtInIcon = ResourceManager.loadImage(BUILT_IN_ICON);
		disabledBuiltInIcon = ResourceManager.getDisabledIcon((ImageIcon) builtInIcon);

		rootIcon = ResourceManager.loadImage(ROOT_ICON);
		openRootIcon = ResourceManager.loadImage(OPEN_ROOT_ICON);

		openFolderIcon = ResourceManager.loadImage(OPEN_FOLDER);
		disabledOpenFolderIcon = ResourceManager.loadImage(DISABLED_OPEN_FOLDER);

		closedFolderIcon = ResourceManager.loadImage(CLOSED_FOLDER);
		disabledClosedFolderIcon = ResourceManager.loadImage(DISABLED_CLOSED_FOLDER);

		lockedOpenFolderIcon = ResourceManager.loadImage(LOCKED_OPEN_FOLDER);
		lockedClosedFolderIcon = ResourceManager.loadImage(LOCKED_CLOSED_FOLDER);

		openArchiveFolderIcon = ResourceManager.loadImage(OPEN_ARCHIVE_FOLDER);
		closedArchiveFolderIcon = ResourceManager.loadImage(CLOSED_ARCHIVE_FOLDER);

		createDataTypeIcons();

	}

	private static void createDataTypeIcons() {
		List<DataTypeIconWrapper> list = new ArrayList<>();

		Icon enumIcon = ResourceManager.loadImage(ENUM_ICON);
		list.add(new DataTypeIconWrapper(Enum.class, enumIcon,
			ResourceManager.getDisabledIcon((ImageIcon) enumIcon)));

		Icon functionIcon = ResourceManager.loadImage(FUNCTION_ICON);
		list.add(new DataTypeIconWrapper(FunctionDefinition.class, functionIcon,
			ResourceManager.getDisabledIcon((ImageIcon) functionIcon)));

		Icon pointerIcon = ResourceManager.loadImage(POINTER_ICON);
		list.add(new DataTypeIconWrapper(Pointer.class, pointerIcon,
			ResourceManager.getDisabledIcon((ImageIcon) pointerIcon)));

		Icon typedefIcon = ResourceManager.loadImage(TYPEDEF_ICON);
		list.add(new DataTypeIconWrapper(TypeDef.class, typedefIcon,
			ResourceManager.getDisabledIcon((ImageIcon) typedefIcon)));

		Icon unionIcon = ResourceManager.loadImage(UNION_ICON);
		list.add(new DataTypeIconWrapper(Union.class, unionIcon,
			ResourceManager.getDisabledIcon((ImageIcon) unionIcon)));

		Icon structureIcon = ResourceManager.loadImage(STRUCTURE_ICON);
		list.add(new DataTypeIconWrapper(Structure.class, structureIcon,
			ResourceManager.getDisabledIcon((ImageIcon) structureIcon)));

		dataTypeIconWrappers = list.toArray(new DataTypeIconWrapper[list.size()]);
	}

	/**
	 * Returns the root folder icon.
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

//    /**
//     * Returns the open archive folder icon.
//     * 
//     * @param isLocked True means to return the checked-out open archive folder icon
//     * @return the open archive folder icon.
//     */
//    public static Icon getOpenProjectArchiveFolder( boolean isLocked ) {
//    	loadImages();
//        if ( isLocked ) {
//            return lockedOpenProjectArchiveFolderIcon;
//        }
//        
//        return openProjectArchiveFolderIcon;
//    }
//    
//    /**
//     * Returns the closed folder icon.
//     * 
//     * @param isLocked True means to return the checked-out closed folder icon
//     * @return the closed folder icon.
//     */
//    public static Icon getClosedProjectArchiveFolder( boolean isLocked ) {
//    	loadImages();
//        if ( isLocked ) {
//            return lockedClosedProjectArchiveFolderIcon;
//        }
//        
//        return closedProjectArchiveFolderIcon;
//    }
//    
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
			highlightIcon = new MultiIcon(new HighlightIcon(new Color(204, 204, 255)));
			highlightIcon.addIcon(baseIcon);
			highlightIconMap.put(baseIcon, highlightIcon);
		}

		return highlightIcon;
	}

	/**
	 * Returns a sorted list of {@link DataType}s that have names which start with the given
	 * search string.   The list is sorted according to {@link #DATA_TYPE_LOOKUP_COMPARATOR}.
	 * 
	  @param searchString The name of the DataTypes to match.
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
	 * Changes the give text to prepare it or use in searching for data types.  Clients should
	 * call this method to make sure that the given text is suitable for use when searching 
	 * the data type values returned by {@link #getExactMatchingDataTypes(String, DataTypeManagerService)}
	 * and {@link #getStartsWithMatchingDataTypes(String, DataTypeManagerService)}.
	 */
	public static String prepareSearchText(String searchText) {
		return searchText.replaceAll(" ", "");
	}

	/*testing*/ static List<DataType> getMatchingSubList(String searchTextStart,
			String searchTextEnd, List<DataType> dataTypeList) {

		searchTextStart = prepareSearchText(searchTextStart);
		searchTextEnd = prepareSearchText(searchTextEnd);

		int startIndex = Algorithms.binarySearchWithDuplicates(dataTypeList, searchTextStart,
			DATA_TYPE_LOOKUP_COMPARATOR);

		int endIndex = Algorithms.binarySearchWithDuplicates(dataTypeList, searchTextEnd,
			DATA_TYPE_LOOKUP_COMPARATOR);

		return dataTypeList.subList(startIndex, endIndex);
	}

	/**
	 * Get the base data type for the specified data type.
	 * <br>For example, the base data type for Word*[5] is Word.
	 * For a pointer, the base data type is the type being pointed to 
	 * or the pointer itself if it is pointing at nothing.
	 * <br>If "INT" is a typedef on a "dword" then INT[7][3] would have a base data type of dword.
	 * If you wanted to get the INT from INT[7][3] 
	 * you should call getNamedBasedDataType(DataType) instead.
	 * @param baseDataType the data type whose base data type is to be determined.
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
	 * Get the named base data type for the specified data type.
	 * This method intentionally does not drill down into typedefs.
	 * <br>For example, the named base data type for Word*[5] is Word.
	 * For a pointer, the named base data type is the type being pointed to 
	 * or the pointer itself if it is pointing at nothing.
	 * <br>If "INT" is a typedef on a "dword", then INT[7][3] would 
	 * have a named base data type of INT.
	 * If you wanted to get the dword from INT[7][3] 
	 * you should call getBasedDataType(DataType) instead.
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
	 * Returns a {@link DataType#copy(DataTypeManager) copy()} of the first named data 
	 * type found in the pointer / array type chain, and returns an identical chain of
	 * pointer / arrays up to the copied named type.
	 * <p>
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
			msg =
				"The archive file is not modifiable!\nYou must open the archive for editing\n before performing this operation.";
		}
		else {
			msg =
				"The project archive is not modifiable!\nYou must check out the archive\n before performing this operation.";
		}
		Msg.showInfo(DataTypeUtils.class, parent, title, msg);

	}

// For testing:	
//	public static void main( String[] args ) {
//	    JFrame frame = new JFrame();
//	    JPanel panel = new JPanel();
//	    
//	    JLabel label1 = new GDLabel();
//	    Icon icon = getOpenFolderIcon( false );
//	    label1.setIcon( icon );
//	    
//	    JLabel label2 = new GDLabel();
//	    Icon icon2 = ResourceManager.getDisabledIcon( (ImageIcon) icon );
//	    label2.setIcon( icon2 );	    	    
//	        
//	    panel.add( label1 );
//	    panel.add( label2 );
//	    
//	    frame.getContentPane().add( panel );
//	    
//	    frame.pack();
//	    frame.setVisible( true );
//	    frame.setDefaultCloseOperation( JFrame.EXIT_ON_CLOSE );
//	}
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

class VersionIcon implements Icon {

	private static Color VERSION_ICON_COLOR_DARK = new Color(0x82, 0x82, 0xff);
	private static Color VERSION_ICON_COLOR_LIGHT = new Color(0x9f, 0x9f, 0xff);

	private static final int WIDTH = 18;
	private static final int HEIGHT = 17;

	int width;
	int height;

	VersionIcon() {
		this(WIDTH, HEIGHT);
	}

	VersionIcon(int width, int height) {
		this.width = width;
		this.height = height;
	}

	@Override
	public int getIconHeight() {
		return height;
	}

	@Override
	public int getIconWidth() {
		return width;
	}

	@Override
	public void paintIcon(Component c, Graphics g, int x, int y) {
		g.setColor(VERSION_ICON_COLOR_LIGHT);
		g.fillRect(x + 1, y + 1, width - 2, height - 2);
		g.setColor(VERSION_ICON_COLOR_DARK);
		g.drawLine(x + 1, y, x + width - 2, y);
		g.drawLine(x + width - 1, y + 1, x + width - 1, y + height - 2);
		g.drawLine(x + 1, y + height - 1, x + width - 2, y + height - 1);
		g.drawLine(x, y + 1, x, y + height - 2);
	}
}
