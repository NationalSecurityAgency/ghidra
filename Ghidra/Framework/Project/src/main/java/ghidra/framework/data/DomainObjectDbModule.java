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

import java.io.IOException;

import ghidra.framework.model.DomainObject;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Common interface for modules in a {@link DomainObject}. Modules manage specific database 
 * subsections of a DomainObject's implementation.
 * @param <T> the DomainObject type which contains this module
 */
public interface DomainObjectDbModule<T extends DomainObjectAdapterDB> {

	/**
	 * Callback from program used to indicate all manager have been created.
	 * When this method is invoked, all managers have been instantiated but may not be fully
	 * initialized.
	 * 
	 * @param dobj the domain object implementation is set when all the initializations have been 
	 * completed.
	 */
	void setDomainObject(T dobj);

	/**
	 * Callback from domain object made to each manager after the all module initializations have 
	 * been completed.  This method may be used by managers to perform additional upgrading which 
	 * may have been deferred.
	 * 
	 * @param openMode the mode that the program is being opened.
	 * @param currentRevision current program revision.  If openMode is UPGRADE, this value reflects 
	 * the pre-upgrade value.
	 * @param monitor the task monitor to use in any upgrade operations.
	 * @throws IOException if a database io error occurs.
	 * @throws CancelledException if the user cancelled the operation via the task monitor.
	 */
	void domainObjectReady(OpenMode openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Clears all data caches. 
	 * 
	 * @param all if false, some managers may not need to update their cache if they can
	 * tell that its not necessary.  If this flag is true, then all managers should clear
	 * their cache no matter what.
	 * @throws IOException if a database io error occurs.
	 */
	void invalidateCache(boolean all) throws IOException;

	/**
	 * Callback from the program after being closed to signal this manager to release memory and 
	 * resources.
	 */
	default void dispose() {
		// default do nothing
	}
}
