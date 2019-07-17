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

import ghidra.framework.model.DomainFile;
import ghidra.util.exception.CancelledException;

/**
 * <code>DefaultCheckinHandler</code> provides a simple
 * check-in handler for use with 
 * {@link DomainFile#checkin(CheckinHandler, boolean, ghidra.util.task.TaskMonitor)}
 */
public class DefaultCheckinHandler implements CheckinHandler {
	
	private final String comment;
	private final boolean keepCheckedOut;
	private final boolean createKeepFile;
	
	public DefaultCheckinHandler(String comment, boolean keepCheckedOut, boolean createKeepFile) {
		this.comment = comment;
		this.keepCheckedOut = keepCheckedOut;
		this.createKeepFile = createKeepFile;
	}

	@Override
	public String getComment() throws CancelledException {
		return comment;
	}

	@Override
	public boolean keepCheckedOut() throws CancelledException {
		return keepCheckedOut;
	}

	@Override
	public boolean createKeepFile() throws CancelledException {
		return createKeepFile;
	}

}
