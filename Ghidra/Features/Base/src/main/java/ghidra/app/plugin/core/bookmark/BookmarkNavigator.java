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
package ghidra.app.plugin.core.bookmark;

import java.awt.Color;

import javax.swing.ImageIcon;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.services.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.util.MarkerLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.Swing;
import resources.ResourceManager;

/**
 * Handles navigation/display of bookmarks in the browser marker margins.
 */
public class BookmarkNavigator {

	private static final int BIG_CHANGE = 1000;

	final static ImageIcon NOTE_ICON = ResourceManager.loadImage("images/notes.gif");
	final static ImageIcon INFO_ICON = ResourceManager.loadImage("images/information.png");
	final static ImageIcon WARNING_ICON = ResourceManager.loadImage("images/warning.png");
	final static ImageIcon ERROR_ICON = ResourceManager.loadImage("images/edit-delete.png");
	final static ImageIcon ANALYSIS_ICON =
		ResourceManager.loadImage("images/applications-system.png");
	final static ImageIcon DEFAULT_ICON = ResourceManager.loadImage("images/unknown.gif");

	final static int NOTE_PRIORITY = MarkerService.BOOKMARK_PRIORITY;
	final static int ERROR_PRIORITY = MarkerService.BOOKMARK_PRIORITY + BIG_CHANGE;
	final static int WARNING_PRIORITY = MarkerService.BOOKMARK_PRIORITY + (BIG_CHANGE / 2);
	final static int INFO_PRIORITY = MarkerService.BOOKMARK_PRIORITY + 4;
	final static int ANALYSIS_PRIORITY = MarkerService.BOOKMARK_PRIORITY + 6;
	final static int DEFAULT_PRIORITY = MarkerService.BOOKMARK_PRIORITY + 8;

	final static Color NOTE_COLOR = new Color(128, 0, 255);     // Purple
	final static Color INFO_COLOR = new Color(0, 255, 255);     // Cyan
	final static Color WARNING_COLOR = new Color(255, 196, 51); // Dark Yellow
	final static Color ERROR_COLOR = new Color(204, 0, 51);     // Dark Red
	final static Color ANALYSIS_COLOR = new Color(255, 128, 0); // Orange
	final static Color DEFAULT_COLOR = new Color(255, 0, 255);  // Magenta

	private String type;
	private MarkerService markerService;
	private BookmarkManager bookmarkMgr;
	private MarkerSet markerSet;
	private Runnable updateRunnable;
	private AddressSet addressSet;

	public BookmarkNavigator(MarkerService markerService, BookmarkManager bookmarkManager,
			BookmarkType bmt) {

		this.markerService = markerService;
		bookmarkMgr = bookmarkManager;
		this.type = bmt.getTypeString();

		updateRunnable = () -> updateMarkerSetAddresses();

		int priority = bmt.getMarkerPriority();
		if (priority < 0) {
			priority = DEFAULT_PRIORITY;
		}

		ImageIcon icon = bmt.getIcon();
		if (icon == null) {
			icon = DEFAULT_ICON;
		}

		Color color = bmt.getMarkerColor();
		if (color == null) {
			color = DEFAULT_COLOR;
		}

		markerSet = markerService.createPointMarker(type + " Bookmarks", type + " Bookmarks",
			bookmarkMgr.getProgram(), priority, true, true, false, color, icon);

		markerSet.setMarkerDescriptor(new MarkerDescriptor() {

			@Override
			public String getTooltip(MarkerLocation loc) {
				Bookmark[] bookmarks = bookmarkMgr.getBookmarks(loc.getAddr(), type);
				if (bookmarks == null) {
					return BookmarkNavigator.this.type;
				}
				StringBuilder buffy = new StringBuilder();
				for (int i = 0; i < bookmarks.length; i++) {
					if (i != 0) {
						buffy.append("<br>");
					}

					buffy.append(BookmarkNavigator.this.type);
					String cat = bookmarks[i].getCategory();
					if (!StringUtils.isBlank(cat)) {
						buffy.append(" [");
						buffy.append(HTMLUtilities.escapeHTML(cat));
						buffy.append("]");
					}
					buffy.append(": ");
					buffy.append(HTMLUtilities.escapeHTML(bookmarks[i].getComment()));
				}
				return buffy.toString();
			}
		});

	}

	private synchronized void updateMarkerSetAddresses() {
		if (addressSet != null && markerSet != null) {
			markerSet.setAddressSet(addressSet);
			addressSet = null;
		}
	}

	/**
	 * Get rid of any local resource connections before this object is disposed of.
	 */
	public void dispose() {
		if (markerService != null) {
			markerService.removeMarker(markerSet, bookmarkMgr.getProgram());
			markerSet = null;
			bookmarkMgr = null;
		}
	}

	/**
	 * Return the type String for the bookmarks 
	 * @return the type
	 */
	String getType() {
		return type;
	}

	/**
	 * Refresh bookmark markers
	 * @param set the addresses
	 */
	public synchronized void updateBookmarkers(AddressSet set) {
		if (addressSet != null) {
			addressSet = set;
			return;
		}
		addressSet = set;
		Swing.runLater(updateRunnable);
	}

	/**
	 * Add bookmark marker at specified address.
	 * @param addr the address
	 */
	public void add(Address addr) {
		markerSet.add(addr);
	}

	/**
	 * Clear bookmark marker at specified address.
	 * @param addr the address
	 */
	public void clear(Address addr) {
		markerSet.clear(addr);
	}

	/**
	 * Return whether the marker set intersections with the given range. 
	 * @param start start of the range
	 * @param end end of the range
	 * @return true if intersects
	 */
	public boolean intersects(Address start, Address end) {
		return markerSet.intersects(start, end);
	}

	/**
	 * Define the bookmark types, as this information is not maintained in the program
	 * @param program the program
	 */
	public static void defineBookmarkTypes(Program program) {
		BookmarkManager mgr = program.getBookmarkManager();
		mgr.defineType(BookmarkType.NOTE, NOTE_ICON, NOTE_COLOR, NOTE_PRIORITY);
		mgr.defineType(BookmarkType.INFO, INFO_ICON, INFO_COLOR, INFO_PRIORITY);
		mgr.defineType(BookmarkType.WARNING, WARNING_ICON, WARNING_COLOR, WARNING_PRIORITY);
		mgr.defineType(BookmarkType.ERROR, ERROR_ICON, ERROR_COLOR, ERROR_PRIORITY);
		mgr.defineType(BookmarkType.ANALYSIS, ANALYSIS_ICON, ANALYSIS_COLOR, ANALYSIS_PRIORITY);
	}

}
