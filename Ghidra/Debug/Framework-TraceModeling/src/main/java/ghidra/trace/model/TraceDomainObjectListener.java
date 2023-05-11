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
package ghidra.trace.model;

import ghidra.framework.model.*;
import ghidra.util.TimedMsg;

public class TraceDomainObjectListener extends TypedEventDispatcher
		implements DomainObjectListener {

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		//TimedMsg.info(this, "Handing (" + this + "): " + ev);
		if (restoredHandler != null && ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			for (DomainObjectChangeRecord rec : ev) {
				if (rec.getEventType() == DomainObject.DO_OBJECT_RESTORED) {
					restoredHandler.accept(rec);
					TimedMsg.debug(this, "  Done: OBJECT_RESTORED");
					return;
				}
			}
			throw new AssertionError();
		}
		//Map<String, Integer> CountsByType = new TreeMap<>();
		for (DomainObjectChangeRecord rec : ev) {
			handleChangeRecord(rec);
		}
		//TimedMsg.info(this, "  Done: " + CountsByType);
	}
}
