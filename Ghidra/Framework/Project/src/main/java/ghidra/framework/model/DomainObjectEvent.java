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
 * Basic event types for all Domain Objects.
 */
public enum DomainObjectEvent implements EventType {
	SAVED,						// the DomainObject was saved
	FILE_CHANGED, 				// the associated DomainFile changed (file moved, renamed, etc.)
	RENAMED, 					// the DomainObject was renamed
	RESTORED, 					// the DomainObject was changed, all data should be assumed stale
	PROPERTY_CHANGED, 			// a generic property of this DomainObject changed
	CLOSED, 					// the DomainObject was closed
	ERROR;						// a fatal error occurred

	private final int id = DomainObjectEventIdGenerator.next();

	@Override
	public int getId() {
		return id;
	}

}
