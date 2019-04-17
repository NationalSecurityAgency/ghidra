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
package ghidra.framework.main;

import java.io.IOException;

import ghidra.framework.client.ClientUtil;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * A modal task that gets a domain object for a specific version.
 * 
 * 
 */ 
public class GetVersionedObjectTask extends Task {

	private Object consumer;
	private DomainFile domainFile;
	private int versionNumber;
	private DomainObject versionedObj;
	
	/**
	 * Constructor; task will get a read only domain object
	 * @param consumer consumer of the domain object
	 * @param domainFile domain file
	 * @param versionNumber version
	 */
	public GetVersionedObjectTask(Object consumer,  DomainFile domainFile, 
			int versionNumber) {
		this(consumer, domainFile, versionNumber, true);
	}
	/**
	 * Constructor
	 * @param consumer consumer of the domain object
	 * @param domainFile domain file
	 * @param versionNumber version
	 * @param readOnly true if the object should be read only versus
	 * immutable
	 */
	public GetVersionedObjectTask(Object consumer,  DomainFile domainFile, 
		int versionNumber, boolean readOnly) {
		
		super("Get Versioned Domain Object", true, false, true);
		this.consumer = consumer;
		this.domainFile = domainFile;
		this.versionNumber = versionNumber;
	}
	
	/* (non-Javadoc)
	 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
	 */
	@Override
    public void run(TaskMonitor monitor) {
		try {
			monitor.setMessage("Getting Version " + versionNumber +
				" for " + domainFile.getName());
			versionedObj = 
				domainFile.getReadOnlyDomainObject(consumer, versionNumber, 
												   monitor); 
		}catch (CancelledException e) {
		}catch (IOException e) {
			if (domainFile.isInWritableProject()) {
				ClientUtil.handleException(AppInfo.getActiveProject().getRepository(), e, 
						"Get Versioned Object", null);
			}
			else {
				Msg.showError(this, null, 
					"Error Getting Versioned Object", "Could not get version " + versionNumber + 
					" for "  + domainFile.getName() + ": " + e, e);
			}
		} catch (VersionException e) {
			Msg.showError(this, 
				null,
				"Error Getting Versioned Object", "Could not get version " + versionNumber + 
				" for "  + domainFile.getName() + ": " + e); 
		}
	}
	/**
	 * Return the versioned domain object.
	 */
	public DomainObject getVersionedObject() {
		return versionedObj;
	}
}
