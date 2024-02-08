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
 * Interface for objects that represent event types. This interface has only one method and that
 * method exists to facilitate fast checking if an event type is present in a collection of events.
 * The value returned from getId() is arbitrary and can change from run to run. Its only purpose
 * is to give each event type a unique compact id that can be used as an index into a bit set. It is
 * important that implementers of this interface get their id values by calling 
 * {@link DomainObjectEventIdGenerator#next()} so that all event ids are coordinated and as 
 * small as possible.
 * <P>
 * The preferred implementation of EventType is an enum that enumerates the valid event types
 * for any application sub-system. See {@link DomainObjectEvent} for an example implementation.
 * 
 */
public interface EventType {

	/**
	 * Returns the unique id assigned to this event type. The value is guaranteed to be constant
	 * for any given run of the application, but can vary from run to run.
	 * @return the unique event id assigned to this EventType.
	 */
	public int getId();
}
