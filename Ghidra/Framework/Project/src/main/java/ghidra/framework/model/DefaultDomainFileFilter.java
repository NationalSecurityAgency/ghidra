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
 * {@link DefaultDomainFileFilter} provides a simple default domain file filter which accepts
 * files for a specified domain object interface class. 
 */
public class DefaultDomainFileFilter implements DomainFileFilter {

	private final Class<? extends DomainObject> domainObjectClass;
	private final boolean ignoreExternalLinks;

	/**
	 * Construct a {@link DomainFileFilter} which accepts a specific domain object interface
	 * class and either shows or hides external links.  If external links are not ignored
	 * the filter will allow following external folder-links into other projects or server 
	 * repositories.  Note that this should be enabled carefully since it may required 
	 * proper repository authentication support to facilitate access.
	 * Broken links are always ignored and all internal linked-folders and linked-files will be
	 * followed/processed.   
	 * 
	 * @param domainObjectClass domain object interface class. May be null to disallow all files
	 * (i.e., only folders and folder-links are shown).
	 * @param ignoreExternalLinks true to ignore/skip external links, else they will be 
	 * shown/processed and opening/following such links will be supported.
	 */
	public DefaultDomainFileFilter(Class<? extends DomainObject> domainObjectClass,
			boolean ignoreExternalLinks) {
		this.domainObjectClass = domainObjectClass;
		this.ignoreExternalLinks = ignoreExternalLinks;
	}

	@Override
	public boolean accept(DomainFile file) {
		return domainObjectClass != null &&
			domainObjectClass.isAssignableFrom(file.getDomainObjectClass());
	}

	@Override
	public boolean ignoreExternalLinks() {
		return ignoreExternalLinks;
	}

}
