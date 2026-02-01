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

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;

/**
 * Listener for when the {@link DomainFile} associated with a {@link DomainObject} changes, such
 * as when a 'Save As' action occurs. Unlike DomainObject events, these callbacks are not buffered
 * and happen immediately when the DomainFile is changed.
 */
public interface DomainObjectFileListener {
	/**
	 * Notification that the DomainFile for the given DomainObject has changed
	 * @param domainObject the DomainObject whose DomainFile changed
	 */
	public void domainFileChanged(DomainObject domainObject);
}
