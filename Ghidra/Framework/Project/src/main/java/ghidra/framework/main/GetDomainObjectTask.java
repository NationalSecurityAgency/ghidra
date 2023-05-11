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
package ghidra.framework.main;

import java.io.IOException;

import docking.widgets.OptionDialog;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.util.VersionExceptionHandler;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * A modal task that gets a domain object for a specified version.
 * Object is either open read-only or immutable.  
 * 
 * NOTE: This task is not intended to open a domain file for modification and saving back 
 * to a project.
 * 
 * A file open for read-only use will be upgraded if needed and is possible.  Once open it is 
 * important that the specified consumer be released from the domain object when done using 
 * the open object (see {@link DomainObject#release(Object)}).
 */ 
public class GetDomainObjectTask extends Task {

	private Object consumer;
	private DomainFile domainFile;
	private int versionNumber;
	private boolean immutable;

	private DomainObject versionedObj;
	
	/**
	 * Construct task open specified domainFile read only.  
	 * An upgrade is performed if needed and is possible.
	 * @param consumer consumer of the domain object
	 * @param domainFile domain file
	 * @param versionNumber version
	 */
	public GetDomainObjectTask(Object consumer, DomainFile domainFile, int versionNumber) {
		this(consumer, domainFile, versionNumber, false);
	}

	/**
	 * Construct task open specified domainFile read only or immutable.  Immutable mode should not
	 * be used for content that will be modified.
	 * If read-only an upgrade is performed if needed, if immutable the user will be prompted
	 * if an upgrade should be performed if possible in which case it will open read-only.
	 * @param consumer consumer of the domain object
	 * @param domainFile domain file
	 * @param versionNumber version
	 * @param immutable true if the object should be open immutable, else read-only.
	 */
	public GetDomainObjectTask(Object consumer, DomainFile domainFile, int versionNumber,
			boolean immutable) {
		super("Get Versioned Domain Object", true, false, true);
		this.consumer = consumer;
		this.domainFile = domainFile;
		this.versionNumber = versionNumber;
		this.immutable = immutable;
	}
	
	@Override
    public void run(TaskMonitor monitor) {
		String contentType = domainFile.getContentType();
		try {
			monitor.setMessage("Getting Version " + versionNumber + " for " + domainFile.getName());
			if (immutable) {
				versionedObj =
					domainFile.getImmutableDomainObject(consumer, versionNumber, monitor);
			}
			else {
				// Upgrade will be performed if required
				versionedObj = domainFile.getReadOnlyDomainObject(consumer, versionNumber, monitor);
			}
		}
		catch (CancelledException e) {
			// ignore
		}
		catch (IOException e) {
			ClientUtil.handleException(AppInfo.getActiveProject().getRepository(), e,
				contentType + " Open", null);
		} catch (VersionException e) {
			if (immutable && e.isUpgradable()) {
				String detailMessage =
					e.getDetailMessage() == null ? "" : "\n" + e.getDetailMessage();
				String title = "Upgrade " + contentType + " Data? " + domainFile.getName();
				String message = "The " + contentType + " file you are attempting to open" +
					" is an older version." + detailMessage + "\n \n" +
					"Would you like to Upgrade it now?";
				int rc = OptionDialog.showOptionDialog(null, title, message, "Upgrade",
					OptionDialog.QUESTION_MESSAGE);
				if (rc == OptionDialog.OPTION_ONE) {
					// try again as read-only
					immutable = false;
					run(monitor);
				}
				return;
			}
			VersionExceptionHandler.showVersionError(null, domainFile.getName(),
				domainFile.getContentType(), contentType + " Open", e);
		}
	}
	
	/**
	 * Return the domain object instance.
	 * @return domain object which was opened or null if task cancelled or failed
	 */
	public DomainObject getDomainObject() {
		return versionedObj;
	}
}
