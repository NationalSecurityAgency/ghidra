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
package ghidra.app.plugin.core.datamgr.archive;

import ghidra.app.merge.DataTypeManagerOwner;
import ghidra.util.exception.DuplicateFileException;

import java.awt.Component;
import java.io.IOException;

import javax.swing.ImageIcon;

/**
 * This is an interface for data type archives.
 */
public interface Archive extends DataTypeManagerOwner, Comparable<Archive> {

	/**
	 * Gets the name for this data type archive.
	 * This is the name to be presented to the user for this archive.
	 * @return the name
	 */
	public String getName();

	/**
	 * Closes this archive.  Some archives cannot be closed (i.e. BuiltIn data type archive.)
	 */
	public void close();

	/**
	 * Determines if this is a modifiable archive like a program archive, a non-versioned
	 * project archive, a checked out versioned project archive or a locked (open for editing)
	 * file archive.
	 * @return true if it is a modifiable archive and can have its contents changed.
	 */
	public boolean isModifiable();

	/**
	 * Determines if this archive can be saved. Some archives cannot be saved.
	 * @return true if the archive can be saved.
	 */
	public boolean isSavable();

	/**
	 * Determines if this archive has been changed. Some archives cannot be changed.
	 * @return true if the archive contains unsaved changes.
	 */
	public boolean isChanged();

	/**
	 * Saves this archive. Some archives cannot be saved.
	 */
	public void save() throws DuplicateFileException, IOException;

	/**
	 * Saves this archive to a newly named file.
	 * @param component
	 * @throws IOException
	 */
	public void saveAs(Component component) throws IOException;

	/**
	 * Gets the icon representing this archive.
	 * @param expanded true means show the icon for this archive as an expanded (open) tree node.
	 * false indicates the node is closed.
	 * @return the archive's icon.
	 */
	public ImageIcon getIcon(boolean expanded);
}
