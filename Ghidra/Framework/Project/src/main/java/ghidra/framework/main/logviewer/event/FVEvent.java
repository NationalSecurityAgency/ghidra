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
package ghidra.framework.main.logviewer.event;

/**
 * Custom events to be used in conjunction with the {@link FVEventListener} module. Users should
 * construct an event, then fire it using {@link FVEventListener#send(FVEvent)}.
 * 
 * Two items are passed along with each event:
 * 	- The {@link #eventType} attribute specifies the event that is being fired.
 * 	- The {@link #arg} is a generic object and can be populated with whatever is appropriate for the
 * associated event. It's up to the receiver to understand how to parse it.
 *
 */
public class FVEvent {

	public static enum EventType {
		COPY_SELECTION,
		DECREMENT_SELECTION,
		DECREMENT_AND_ADD_SELECTION,
		FILE_CHANGED,
		INCREMENT_SELECTION,
		INCREMENT_AND_ADD_SELECTION,
		OPEN_FILE_LOCATION,
		RELOAD_FILE,
		SLIDER_CHANGED,
		SCROLL_LOCK_OFF,
		SCROLL_LOCK_ON,
		VIEWPORT_UPDATE,
		VIEWPORT_UP,
		VIEWPORT_DOWN,
		VIEWPORT_PAGE_UP,
		VIEWPORT_PAGE_DOWN,
		SCROLL_HOME,
		SCROLL_END,
		SCROLL_END_2
	}

	public EventType eventType;
	public Object arg;

	/**
	 * 
	 * @param eventType
	 * @param arg
	 */
	public FVEvent(EventType eventType, Object arg) {
		this.eventType = eventType;
		this.arg = arg;
	}
}
