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
package ghidra.util.filechooser;

import java.io.File;
import java.io.FileFilter;
import java.util.List;

import javax.swing.Icon;

import utility.function.Callback;

/**
 * Interface for the GhidraFileChooser data model.
 * This allows the GhidraFileChooser to operate
 * on files from different sources, other than
 * just the local file system.
 */
public interface GhidraFileChooserModel {
	/**
	 * Set the model update callback.
	 * 
	 * @param callback the new model update callback handler
	 */
	public void setModelUpdateCallback(Callback callback);

	/**
	 * Returns the home directory.
	 * 
	 * @return the home directory
	 */
	public File getHomeDirectory();

	/**
	 * Returns the user's desktop directory, as defined by their operating system and/or their windowing environment, or
	 * null if there is no desktop directory.<p>
	 * Example: "/home/the_user/Desktop" or "c:/Users/the_user/Desktop"
	 * 
	 * @return desktop directory
	 */
	public File getDesktopDirectory();

	/**
	 * Returns the user's downloads directory, as defined by their operating system and/or their windowing environment, or
	 * null if there is no downloads directory.<p>
	 * Example: "/home/the_user/Downloads" or "c:/Users/the_user/Downloads"
	 * 
	 * @return downloads directory
	 */
	public File getDownloadsDirectory();

	/**
	 * Returns a list of the root drives/directories.
	 * <p>
	 * On windows, "C:\", "D:\", etc.
	 * <p>
	 * On linux, "/".
	 * 
	 * @param forceUpdate if true, request a fresh listing, if false allow a cached result 
	 * @return the root drives
	 */
	public List<File> getRoots(boolean forceUpdate);

	/**
	 * Returns an array of the files that 
	 * exist in the specified directory.
	 * 
	 * @param directory the directory
	 * @param filter the file filter; may be null
	 * @return list of files
	 */
	public List<File> getListing(File directory, FileFilter filter);

	/**
	 * Returns an icon for the specified file.
	 * 
	 * @param file the file
	 * @return an icon for the specified file
	 */
	public Icon getIcon(File file);

	/**
	 * Returns a description for the specified file.
	 * @param file the file
	 * @return a description for the specified file
	 */
	public String getDescription(File file);

	/**
	 * Creates a directory in the specified directory with the specified
	 * name.
	 * @param directory the directory in which to create the new directory
	 * @param name the name of the directory
	 * @return true if the new directory was create.
	 */
	public boolean createDirectory(File directory, String name);

	/**
	 * Tests whether the file denoted by this abstract pathname is a directory.
	 * @param file the file
	 * @return <code>true</code> if and only if the file denoted by this
	 *          abstract pathname exists <em>and</em> is a directory;
	 *          <code>false</code> otherwise
	 */
	public boolean isDirectory(File file);

	/**
	 * Tests whether this abstract pathname is absolute.  The definition of
	 * absolute pathname is system dependent.  On UNIX systems, a pathname is
	 * absolute if its prefix is <code>"/"</code>.  On Microsoft Windows systems, a
	 * pathname is absolute if its prefix is a drive specifier followed by
	 * <code>"\\"</code>, or if its prefix is <code>"\\"</code>.
	 * @param file the file
	 * @return  <code>true</code> if this abstract pathname is absolute,
	 *          <code>false</code> otherwise
	 */
	public boolean isAbsolute(File file);

	/**
	 * Renames the src file to the destination file.
	 * @param src   the file to be renamed
	 * @param dest  the new file
	 * @return true if the file was renamed
	 */
	public boolean renameFile(File src, File dest);

	/**
	 * Returns the file separator char.
	 * On windows, '\'
	 * On linux, '/'.
	 * @return the file separator char
	 */
	public char getSeparator();
}
