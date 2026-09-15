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
package ghidra.framework.data;

/**
 * Dummy domain object to satisfy {@link FolderLinkContentHandler#getDomainObjectClass()}
 */
public final class NullFolderDomainObject extends DomainObjectAdapterDB {
	private NullFolderDomainObject() {
		// this object may not be instantiated
		super(null, null, 0, NullFolderDomainObject.class);
		throw new RuntimeException("Object may not be instantiated");
	}

	@Override
	public boolean isChangeable() {
		return false;
	}

	@Override
	public String getDescription() {
		return "Dummy FolderLink Domain Object";
	}
}
