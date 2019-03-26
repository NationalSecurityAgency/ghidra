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
package ghidra.program.model.listing;

import java.awt.Color;

import javax.swing.ImageIcon;

/**
 * Interface for bookmark types.
 */
public interface BookmarkType {

	public static final String NOTE = "Note";
	public static final String INFO = "Info";
	public static final String ERROR = "Error";
	public static final String WARNING = "Warning";
	public static final String ANALYSIS = "Analysis";
	public static final String ALL_TYPES = "All Bookmark Types";

	/**
	 * Returns the type as a string
	 */
	String getTypeString();

	/**
	 * Returns Icon associated with this type or null if one has not been 
	 * set by a plugin.
	 */
	ImageIcon getIcon();

	/**
	 * Returns marker color associated with this type or null if one has not been 
	 * set by a plugin.
	 */
	Color getMarkerColor();

	/**
	 * Returns marker priority associated with this type or -1 if one has not been 
	 * set by a plugin.
	 */
	int getMarkerPriority();

	/**
	 * Returns true if there is at least one bookmark defined for this type
	 */
	boolean hasBookmarks();

	/**
	 * Returns the id associated with this bookmark type.
	 */
	int getTypeId();
}
