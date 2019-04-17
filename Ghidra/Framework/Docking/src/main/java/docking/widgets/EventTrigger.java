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
package docking.widgets;

/**
 * This class is used to provide information regarding the source of an event.   It is often 
 * useful for event processing clients to know of the user generated an event through the UI 
 * or from an API call, or if the event came from an internal source, like a change to the 
 * client's model.
 */
public enum EventTrigger {
	GUI_ACTION,   // change initiated by a widget from a GUI action (like a mouse click)
	API_CALL,     // change triggered by a programmatic API call 
	MODEL_CHANGE, // change triggered by a change to the underlying data model
	INTERNAL_ONLY // change that is for internal use, not to be propagated
}
