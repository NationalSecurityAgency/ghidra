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
package ghidra.app.plugin.core.datamgr.tree;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;

/**
 * Common interface for DataTypeStoreNodes that support versioning.
 */
public interface VersionedNode {
	/**
	 * {@return the domainObject (this will be the program or archive)}
	 */
	public DomainObject getDomainObject();

	/**
	 * {@return the actual project DomainFile that was used to open this DataTypeStore}
	 */
	public DomainFile getOriginalDomainFile();

	/**
	 * {@return the current DomainFile associated with this DataTypeStore. This may be a proxy}
	 * if the program or archive was opened read-only
	 */
	public DomainFile getDomainFile();

	/**
	 * {@return a string that describes the current version state of this program or archive}
	 */
	public String getDomainObjectInfo();
}
