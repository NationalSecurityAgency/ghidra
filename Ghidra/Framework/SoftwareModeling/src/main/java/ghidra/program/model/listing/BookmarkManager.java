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
package ghidra.program.model.listing;

import java.awt.Color;
import java.util.Iterator;

import javax.swing.ImageIcon;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Interface for managing bookmarks.
 */
public interface BookmarkManager {

	//
	// In the beginning ... a bookmark was stored as a property object associated
	// with an address location.  Property objects are still supported and 
	// managed by the DBPropertyMapManager.  DBPropertyMapManager has been modified to
	// generate a VersionException if a bookmark property map exists for either of these
	// bookmark classes except in the upgrade case.  When upgrading, the  
	// DBPropertyMapManager will utilize the OldBookmark class to store the old 
	// bookmark properties, which may then be converted to the new storage mechanism 
	// supported by this bookmark manager.
	//

	/**
	 * 1st version of bookmark property object class (schema change and class moved)
	 */
	public static final String OLD_BOOKMARK_PROPERTY_OBJECT_CLASS1 =
		"ghidra.app.plugin.bookmark.BookmarkInfo";

	/**
	 * 2nd version of bookmark property object class (class moved, property map no longer used)
	 */
	public static final String OLD_BOOKMARK_PROPERTY_OBJECT_CLASS2 = "ghidra.program.util.Bookmark";

	/**
	 * Define a bookmark type with its marker icon and color.  The icon and color
	 * values are not permanently stored.  Therefor, this method must be re-invoked
	 * by a plugin each time a program is opened if a custom icon and color 
	 * are desired.
	 * @param type bookmark type
	 * @param icon marker icon which may get scaled
	 * @param color marker color
	 * @param priority the bookmark priority
	 * @return bookmark type object
	 * @throws IllegalArgumentException if any of the arguments are null or if the type is empty 
	 */
	BookmarkType defineType(String type, ImageIcon icon, Color color, int priority);

	/**
	 * Returns list of known bookmark types
	 * @return list of known bookmark types
	 */
	BookmarkType[] getBookmarkTypes();

	/**
	 * Get a bookmark type
	 * @param type bookmark type name
	 * @return bookmark type or null if type is unknown
	 */
	BookmarkType getBookmarkType(String type);

	/**
	 * Get list of categories used for a specified type
	 * @param type bookmark type
	 * @return array of category strings
	 */
	String[] getCategories(String type);

	/**
	 * Set a bookmark.
	 * @param addr the address at which to set a bookmark
	 * @param type the name of the bookmark type.
	 * @param category the category for the bookmark.
	 * @param comment the comment to associate with the bookmark.
	 * @return the new bookmark
	 */
	Bookmark setBookmark(Address addr, String type, String category, String comment);

	/**
	 * Get a specific bookmark
	 * @param addr the address of the bookmark to retrieve
	 * @param type the name of the bookmark type.
	 * @param category the category of the bookmark.
	 * @return the bookmark with the given attributes, or null if no bookmarks match.
	 */
	Bookmark getBookmark(Address addr, String type, String category);

	/**
	 * Remove bookmark 
	 * @param bookmark the bookmark to remove.
	 */
	void removeBookmark(Bookmark bookmark);

	/**
	 * Removes all bookmarks of the given type.
	 * @param type bookmark type
	 */
	void removeBookmarks(String type);

	/**
	 * Removes all bookmarks with the given type and category.
	 * @param type the type of the bookmarks to be removed.
	 * @param category bookmark category of the types to be removed.
	 * @param monitor a task monitor to report the progress.
	 * @throws CancelledException if the user (via the monitor) cancelled the operation.
	 */
	void removeBookmarks(String type, String category, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Removes all bookmarks over the given address set.
	 * @param set the set of addresses from which to remove all bookmarks.
	 * @param monitor a task monitor to report the progress.
	 * @throws CancelledException if the user (via the monitor) cancelled the operation.
	 */
	void removeBookmarks(AddressSetView set, TaskMonitor monitor) throws CancelledException;

	/**
	 * Removes all bookmarks of the given type over the given address set
	 * @param set the set of addresses from which to remove all bookmarks of the given type.
	 * @param type the type of bookmarks to remove.
	 * @param monitor a task monitor to report the progress.
	 * @throws CancelledException if the user (via the monitor) cancelled the operation.
	 */
	void removeBookmarks(AddressSetView set, String type, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Removes all bookmarks of the given type and category over the given address set
	 * @param set the set of addresses from which to remove all bookmarks of the given type and category.
	 * @param type the type of bookmarks to remove.
	 * @param category the category of bookmarks to remove.
	 * @param monitor a task monitor to report the progress.
	 * @throws CancelledException if the user (via the monitor) cancelled the operation.
	 */
	void removeBookmarks(AddressSetView set, String type, String category, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Get bookmarks of the indicated type on a specific address
	 * @param address the address at which to search for bookmarks.
	 * @param type bookmark type to search for
	 * @return array of bookmarks
	 */
	Bookmark[] getBookmarks(Address address, String type);

	/**
	 * Get all bookmarks on a specific address
	 * @param addr the address at which to retrieve all bookmarks.
	 * @return array of bookmarks
	 */
	public Bookmark[] getBookmarks(Address addr);

	/**
	 * Get addresses for bookmarks of a specified type.
	 * @param type bookmark type
	 * @return address set containing bookmarks of the specified type.
	 */
	AddressSetView getBookmarkAddresses(String type);

	/**
	 * Get iterator over all bookmarks of the specified type.
	 * @param type the bookmark type to search for
	 * @return an iterator over all bookmarks of the specified type.
	 */
	Iterator<Bookmark> getBookmarksIterator(String type);

	/**
	 * Returns an iterator over all bookmarks
	 * @return an iterator over all bookmarks
	 */
	Iterator<Bookmark> getBookmarksIterator();

	/**
	 * Returns an iterator over all bookmark types, starting at the given address, with traversal
	 * in the given direction.
	 * 
	 * @param startAddress the address at which to start
	 * @param forward true to iterate in the forward direction; false for backwards
	 * 
	 * @return an iterator over all bookmark types, starting at the given address, with traversal
	 * 		   in the given direction.
	 */
	Iterator<Bookmark> getBookmarksIterator(Address startAddress, boolean forward);

	/**
	 * Returns the bookmark that has the given id or null if no such bookmark exists.
	 * @param id the id of the bookmark to be retrieved.
	 * @return the bookmark
	 */
	Bookmark getBookmark(long id);

	/**
	 * Returns true if program contains one or more bookmarks of the given type
	 * @param type the type of bookmark to check for.
	 * @return true if program contains one or more bookmarks of the given type
	 */
	boolean hasBookmarks(String type);

	/**
	 * Return the number of bookmarks of the given type
	 * @param type the type of bookmarks to count
	 * @return the number of bookmarks of the given type
	 */
	int getBookmarkCount(String type);

	/**
	 * Returns the total number of bookmarks in the program
	 * @return the total number of bookmarks in the program
	 */
	int getBookmarkCount();

	/**
	 * Returns the program associated with this BookmarkManager.
	 * @return the program associated with this BookmarkManager.
	 */
	Program getProgram();

}
