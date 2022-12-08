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

import java.util.*;
import java.util.stream.Collectors;

import java.io.File;
import java.io.FileFilter;

/**
 * A convenience implementation of FileFilter that filters out
 * all files except for those type extensions that it knows about.
 * <p>
 * Extensions are of the type "foo" (no leading dot). Case is ignored.
 * <p>
 * Example - create a new filter that filters out all files
 * but gif and jpg image files:
 * <pre>
 *     GhidraFileChooser chooser = new GhidraFileChooser();
 *     chooser.addFileFilter(ExtensionFilFilter.forExtensions("JPEG and GIF Images", "gif", "jpg"));
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

	private List<String> extensions;
	private String description;
	private String fullDescription;

	/**
	 * Creates a file filter that accepts the given file type.
	 * Example: new ExtensionFileFilter("jpg", "JPEG Images");
	 *
	 * @param extension file extension to match, without leading dot
	 * @param description descriptive string of the filter
	 */
	public ExtensionFileFilter(String extension, String description) {
		this(new String[] { extension }, description);
	}

	/**
	 * Creates a file filter from the given string array and description.
	 * Example: new ExtensionFileFilter(String {"gif", "jpg"}, "Gif and JPG Images");
	 *
	 * @param filters array of file name extensions, each without a leading dot
	 * @param description descriptive string of the filter
	 */
	public ExtensionFileFilter(String[] filters, String description) {
		this.extensions = Arrays.asList(filters)
				.stream()
				.map(String::toLowerCase)
				.collect(Collectors.toList());
		this.description = description;
	}

	/**
	 * Return true if this file should be shown in the directory pane,
	 * false if it shouldn't.
	 *
	 * Files that begin with "." are ignored.
	 *
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
		if (extensions.isEmpty()) {
			return true;
		}
		String filename = f.getName().toLowerCase();
		if (filename.startsWith(".")) {
			return false;
		}
		int fnLen = filename.length();
		for (String ext : extensions) {
			int extLen = ext.length();
			int extStart = fnLen - extLen;
			if (extStart > 0 && filename.substring(extStart).equals(ext) &&
				filename.charAt(extStart - 1) == '.') {
				return true;
			}
		}
		return false;
	}

	@Override
	public String getDescription() {
		if (fullDescription == null) {
			fullDescription = Objects.requireNonNullElse(description, "");

			// add prettified extensions to the description string
			fullDescription += " (";
			fullDescription += extensions.isEmpty()
					? "*.*"
					: extensions.stream().map(s -> "*." + s).collect(Collectors.joining(","));
			fullDescription += ")";
		}
		return fullDescription;
	}
}
