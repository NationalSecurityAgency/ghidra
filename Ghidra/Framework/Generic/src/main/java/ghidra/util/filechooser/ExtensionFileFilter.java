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
import java.util.Enumeration;
import java.util.Hashtable;

/**
 * A convenience implementation of FileFilter that filters out
 * all files except for those type extensions that it knows about.
 *
 * Extensions are of the type ".foo", which is typically found on
 * Windows and Unix boxes, but not on Mac. Case is ignored.
 *
 * Example - create a new filter that filters out all files
 * but gif and jpg image files:
 * <pre>
 *     GhidraFileChooser chooser = new GhidraFileChooser();
 *     ExtensionFileFilter filter = new ExtensionFileFilter(
 *                   new String{"gif", "jpg"}, "JPEG and GIF Images")
 *     chooser.addFileFilter(filter);
 *</pre>
 */
public class ExtensionFileFilter implements GhidraFileFilter {

	/**
	 * Creates a {@link ExtensionFileFilter} in a varargs friendly way.
	 *
	 * @param description String description of this set of file extensions.
	 * @param exts variable length list of file extensions, without leading dot.
	 * @return new {@link ExtensionFileFilter} instance.
	 */
	public static ExtensionFileFilter forExtensions(String description, String... exts) {
		ExtensionFileFilter eff = new ExtensionFileFilter(exts, description);
		return eff;
	}

	private Hashtable<String, ExtensionFileFilter> filters = null;
	private String description = null;
	private String fullDescription = null;
	private boolean useExtensionsInDescription = true;

	/**
	 * Creates a file filter that accepts the given file type.
	 * Example: new ExtensionFileFilter("jpg", "JPEG Image Images");
	 *
	 * Note that the "." before the extension is not needed. If
	 * provided, it will be ignored.
	 *
	 * @see #addExtension
	 */
	public ExtensionFileFilter(String extension, String description) {
		this(new String[] { extension }, description);
	}

	/**
	 * Creates a file filter from the given string array and description.
	 * Example: new ExtensionFileFilter(String {"gif", "jpg"}, "Gif and JPG Images");
	 *
	 * Note that the "." before the extension is not needed and will be ignored.
	 *
	 * @see #addExtension
	 */
	public ExtensionFileFilter(String[] filters, String description) {
		this.filters = new Hashtable<String, ExtensionFileFilter>(filters.length);
		for (String filter : filters) {
			addExtension(filter);//add filters one by one
		}
		setDescription(description);
	}

	/**
	 * Return true if this file should be shown in the directory pane,
	 * false if it shouldn't.
	 *
	 * Files that begin with "." are ignored.
	 *
	 * @see #getExtension
	 * @see FileFilter#accept
	 */
	@Override
	public boolean accept(File f, GhidraFileChooserModel model) {
		if (f == null) {
			return false;
		}
		if (model.isDirectory(f)) {
			return true;
		}
		if (filters.size() == 0) {
			return true;
		}
		String extension = getExtension(f);
		return extension != null && filters.get(extension) != null;
	}

	/**
	 * Return the extension portion of the file's name .
	 *
	 * @see #getExtension
	 * @see FileFilter#accept
	 */
	public String getExtension(File f) {
		if (f != null) {
			String filename = f.getName();
			int i = filename.lastIndexOf('.');
			if (i > 0 && i < filename.length() - 1) {
				return filename.substring(i + 1).toLowerCase();
			}
		}
		return null;
	}

	/**
	 * Adds a filetype "dot" extension to filter against.
	 *
	 * For example: the following code will create a filter that filters
	 * out all files except those that end in ".jpg" and ".tif":
	 *
	 *   ExtensionFileFilter filter = new ExtensionFileFilter();
	 *   filter.addExtension("jpg");
	 *   filter.addExtension("tif");
	 *
	 * Note that the "." before the extension is not needed and will be ignored.
	 */
	public void addExtension(String extension) {
		if (filters == null) {
			filters = new Hashtable<String, ExtensionFileFilter>(5);
		}
		filters.put(extension.toLowerCase(), this);
		fullDescription = null;
	}

	/**
	 * Returns the human readable description of this filter. For
	 * example: "JPEG and GIF Image Files (*.jpg, *.gif)"
	 */
	@Override
	public String getDescription() {
		if (fullDescription == null) {
			fullDescription = "";
			if (description == null || isExtensionListInDescription()) {
				if (description != null) {
					fullDescription = description;
				}
				fullDescription += " (";
				// build the description from the extension list

				if (filters.size() == 0) {
					fullDescription += "*.*";
				}
				else {
					boolean firstExt = true;
					Enumeration<String> extensions = filters.keys();
					if (extensions != null) {
						while (extensions.hasMoreElements()) {
							if (!firstExt) {
								fullDescription += ",";
							}
							else {
								firstExt = false;
							}
							fullDescription += "*." + extensions.nextElement();
						}
					}
				}
				fullDescription += ")";
			}
			else {
				fullDescription = description;
			}
		}
		return fullDescription;
	}

	/**
	 * Sets the human readable description of this filter. For
	 * example: filter.setDescription("Gif and JPG Images");
	 *
	 * @see #setDescription
	 * @see #setExtensionListInDescription
	 * @see #isExtensionListInDescription
	 */
	public void setDescription(String description) {
		this.description = description;
		fullDescription = null;
	}

	/**
	 * Determines whether the extension list (.jpg, .gif, etc) should
	 * show up in the human readable description.
	 *
	 * Only relevant if a description was provided in the constructor
	 * or using setDescription();
	 *
	 * @see #getDescription
	 * @see #setDescription
	 * @see #isExtensionListInDescription
	 */
	public void setExtensionListInDescription(boolean b) {
		useExtensionsInDescription = b;
		fullDescription = null;
	}

	/**
	 * Returns whether the extension list (.jpg, .gif, etc) should
	 * show up in the human readable description.
	 *
	 * Only relevant if a description was provided in the constructor
	 * or using setDescription();
	 *
	 * @see #getDescription
	 * @see #setDescription
	 * @see #setExtensionListInDescription
	 */
	public final boolean isExtensionListInDescription() {
		return useExtensionsInDescription;
	}
}
