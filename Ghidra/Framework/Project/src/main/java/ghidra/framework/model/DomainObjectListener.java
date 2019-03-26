/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import java.util.EventListener;

/**
 * The interface an object must support to be registered with a Domain Object
 * and thus be informed of changes to the object.
 *   
 * NOTE: The DomainObjectChangeEvent is TRANSIENT: it is only valid during the
 * life of calls to all the DomainObjectChangeListeners.
 * 
 */

public interface DomainObjectListener extends EventListener {
                   
    /**
     * Method called when a change is made to the domain object.
     * @param ev event containing the change record and type of change that
     * was made
     */
    public void domainObjectChanged(DomainObjectChangedEvent ev);
}
