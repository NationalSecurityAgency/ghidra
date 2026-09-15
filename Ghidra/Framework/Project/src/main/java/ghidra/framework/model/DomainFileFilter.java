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

import ghidra.framework.data.LinkHandler;

/**
 * {@link DomainFileFilter} interface to indicate whether a domain file should be included in a 
 * list or set of domain files.  This interface extends {@link DomainFolderFilter} which also
 * controls the following of linked-folders.
 * <P>
 * Without specific overrides the default behavior:
 * <ul>
 * <li>{@link #ignoreBrokenLinks()} (true) Ignores all broken links</li>
 * <li>{@link #ignoreExternalLinks()} (true) Ignores all external links</li>
 * <li>{@link #ignoreFolderLinks()} (false) Will follow folder-links</li>
 * <li>{@link #followExternallyLinkedFolders()} Based on 
 * 			NOT-{@link #ignoreExternalLinks()} AND NOT-{@link #ignoreFolderLinks()} </li>
 * </ul>
 * <P>
 * The specific handling of link-files is determined by the consumer of this filter.
 */
public interface DomainFileFilter extends DomainFolderFilter {

	/**
	 * File filter which accepts all files, including all external file-links,
	 * and allows opening/expanding of external folder-links.  All broken links are ignored.
	 */
	DomainFileFilter ALL_FILES_FILTER = new DomainFileFilter() {
		@Override
		public boolean accept(DomainFile df) {
			return true;
		}

		@Override
		public boolean ignoreExternalLinks() {
			return false;
		}
	};

	/**
	 * File filter which accepts all files, including all external file-links,
	 * but does not allow opening/expanding of external folder-links. All broken links are ignored.
	 */
	DomainFileFilter ALL_FILES_NO_EXTERNAL_FOLDERS_FILTER = new DomainFileFilter() {
		@Override
		public boolean accept(DomainFile df) {
			return true;
		}

		@Override
		public boolean ignoreExternalLinks() {
			return false;
		}

		@Override
		public boolean followExternallyLinkedFolders() {
			return false;
		}
	};

	/**
	 * File filter which allows all internal folders and files.  
	 * All external and broken links are ignored.  This filter is useful when 
	 * selecting a file with an arbitrary content type.  If targeting a specific file content 
	 * type the use of {@link DefaultDomainFileFilter} may be preferred.
	 */
	DomainFileFilter ALL_INTERNAL_FILES_FILTER = new DomainFileFilter() {
		@Override
		public boolean accept(DomainFile df) {
			return true;
		}
	};

	/**
	 * File filter which allows all non-linked internal folders and files.  
	 * All links are ignored.  This filter is useful if code does not handle some of the 
	 * implications of following links such as: 
	 * <ul>
	 * <li>External repository authentication</li>
	 * <li>Processing the same project content more than once or lack of support for link-files</li>
	 * </ul>
	 * If targeting a specific file content type the use of {@link DefaultDomainFileFilter} may 
	 * be preferred.
	 */
	public static DomainFileFilter NON_LINKED_FILE_FILTER = new DomainFileFilter() {

		@Override
		public boolean accept(DomainFile df) {
			// Accept all domain files which are not a link-file.
			// Processing of link-files may result in the same file being returned by the
			// iterator more than once.
			return !df.isLink();
		}

		@Override
		public boolean ignoreFolderLinks() {
			return true;
		}
	};

	/**
	 * Tests whether or not the specified domain file should be included in a domain file list.
	 * Since link-files will also be subject to this constraint the ability to handle or follow
	 * such links must be considered. 
	 * <P>
	 * NOTE: File-links have the same {@link DomainFile#getDomainObjectClass()} as the file they
	 * refer to, while their {@link DomainFile#getContentType()} is specific to their 
	 * {@link LinkHandler} implementation.
	 *
	 * @param  df  The domain file to be tested
	 * @return  <code>true</code> if and only if <code>df</code>
	 */
	public boolean accept(DomainFile df);

	/**
	 * Check if the children of an externally-linked folder should be loaded/processed.
	 * <P>
	 * If this method is not implemented the value returned is 
	 * NOT-{@link #ignoreExternalLinks()} AND NOT-{@link #ignoreFolderLinks()}.
	 * <P>
	 * NOTE: Following an external link utilizes the application's active project to retain
	 * and external project as one of it's viewed-projects.  In the process of accessing a 
	 * viewed-project the user may be required to authenticate to a remote server.
	 * 
	 * @return true if children of an externally-linked folder should be traversed or displayed 
	 * (subject to a successful connection to the referenced project or server-based repository).
	 */
	public default boolean followExternallyLinkedFolders() {
		return !ignoreExternalLinks() && !ignoreFolderLinks();
	}
}
