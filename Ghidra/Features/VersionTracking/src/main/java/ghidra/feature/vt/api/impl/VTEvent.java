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
package ghidra.feature.vt.api.impl;

import ghidra.framework.model.DomainObjectEventIdGenerator;
import ghidra.framework.model.EventType;

public enum VTEvent implements EventType {
	MATCH_SET_ADDED, 					// A match set was added
	ASSOCIATION_STATUS_CHANGED,			// an match association status changed
	ASSOCIATION_MARKUP_STATUS_CHANGED,	// an association markup status changed
	MATCH_ADDED,						// a match was added
	MATCH_DELETED,						// a match was deleted
	MATCH_TAG_CHANGED,					// the tag for a match changed
	ASSOCIATION_ADDED,					// an association was created
	ASSOCIATION_REMOVED,				// an association was deleted
	MARKUP_ITEM_STATUS_CHANGED,			// a markup item's status changed
	MARKUP_ITEM_DESTINATION_CHANGED,	// a markup item's destination changed
	TAG_ADDED,							// a tag type was created
	TAG_REMOVED,						// a tag type was deleted
	VOTE_COUNT_CHANGED;					// the vote count for a match changed

	private final int id = DomainObjectEventIdGenerator.next();

	@Override
	public int getId() {
		return id;
	}

}
