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
package ghidra.program.database.bookmark;

import ghidra.program.model.listing.BookmarkType;

import java.awt.Color;

import javax.swing.ImageIcon;

public class BookmarkTypeDB implements BookmarkType {
	private int typeId;
	private String type;
	private ImageIcon icon;
	private Color markerColor;
	private int priority = -1;
	private boolean hasMarks;	// flag to indicate if this type is stored in the program.

	BookmarkTypeDB(int typeId, String type) {
		this.typeId = typeId;
		this.type = type;
	}

	/*
	 * @see ghidra.program.model.listing.BookmarkType#getTypeString()
	 */
	public String getTypeString() {
		return type;
	}

	void setHasBookmarks(boolean b) {
		hasMarks = b;
	}

	public boolean hasBookmarks() {
		return hasMarks;
	}

	public int getTypeId() {
		return typeId;
	}

	void setIcon(ImageIcon icon) {
		this.icon = icon;
	}

	public ImageIcon getIcon() {
		return icon;
	}

	void setMarkerColor(Color markerColor) {
		this.markerColor = markerColor;
	}

	public Color getMarkerColor() {
		return markerColor;
	}

	void setMarkerPriority(int priority) {
		this.priority = priority;
	}

	public int getMarkerPriority() {
		return priority;
	}

	/*
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		return type;
	}

}
