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
package ghidra.framework.model;

/**
 * {@link DomainFolderFilter} interface to controls the following of linked-folders.
 * <P>
 * Without specific overrides the default behavior:
 * <ul>
 * <li>{@link #ignoreBrokenLinks()} (true) Ignores all broken links</li>
 * <li>{@link #ignoreExternalLinks()} (true) Ignore external folder-links</li>
 * <li>{@link #ignoreFolderLinks()} (false) Will follow internal folder-links</li>
 * </ul>
 */
public interface DomainFolderFilter {

	/**
	 * Folder filter which accepts all folders and will follow all linked folders.
	 * All broken links are ignored.
	 */
	DomainFolderFilter ALL_FOLDERS_FILTER = new DomainFolderFilter() {

		@Override
		public boolean ignoreExternalLinks() {
			return false;
		}
	};

	/**
	 * File filter which allows only folders and internal folder-links.  
	 * All external and broken links are ignored.  This filter is useful when 
	 * selecting a folder when creating/saving a file to the active project.
	 * If targeting a specific file content type for creation or saving use of
	 * {@link DefaultDomainFileFilter} may be preferred.
	 * <P>
	 * It is the consumer of this filter who is responsible for following folder-links.
	 */
	DomainFolderFilter ALL_INTERNAL_FOLDERS_FILTER = new DomainFolderFilter() {
		// Default bahaviors
	};

	/**
	 * Folder filter which accepts only real folders and ignores all folder-links. 
	 * All broken links are ignored.
	 */
	DomainFolderFilter NON_LINKED_FOLDER_FILTER = new DomainFolderFilter() {

		@Override
		public boolean ignoreFolderLinks() {
			return true;
		}
	};

	/**
	 * Check if folder-links should be ignored (includes internal and external).
	 * 
	 * @return true if all folder-links should be ignored (i.e., not followed/displayed)
	 */
	public default boolean ignoreFolderLinks() {
		return false;
	}

	/**
	 * Check if link-files should be ignored if the link is external (i.e., Ghidra-URL).  
	 * Multi-level internal links are followed within the same project before a determination is made.
	 * <P>
	 * If this method is not implemented the default behavior will ignore external links.
	 * This method should be ignored for folder-links if {@link #ignoreFolderLinks()} returns true.
	 * 
	 * @return true if external links should be ignored (i.e., not displayed)
	 */
	public default boolean ignoreExternalLinks() {
		return true;
	}

	/**
	 * Check if link-files should be ignored if the link is broken.  Multi-level internal links 
	 * are followed within the same project before a determination is made.
	 * <P>
	 * If this method is not implemented the default behavior will ignore broken links.
	 * 
	 * @return true if broken links should be ignored (i.e., not followed/displayed)
	 */
	public default boolean ignoreBrokenLinks() {
		return true;
	}

}
