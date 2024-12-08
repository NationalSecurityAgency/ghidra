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
package ghidra.framework.protocol.ghidra;

import java.net.URL;

import ghidra.framework.model.DomainFile;
import ghidra.util.task.TaskMonitor;

/**
 * A blocking/modal Ghidra URL content type discovery task
 */
public class ContentTypeQueryTask extends GhidraURLQueryTask {

	private String contentType = "Unknown";

	/**
	 * Construct a Ghidra URL content type query task
	 * @param ghidraUrl Ghidra URL (local or remote)
	 * @throws IllegalArgumentException if specified URL is not a Ghidra URL
	 * (see {@link GhidraURL}).
	 */
	public ContentTypeQueryTask(URL ghidraUrl) {
		super("Query URL Content Type", ghidraUrl);
	}

	/**
	 * Get the discovered content type (e.g., "Program")
	 * @return content type or null if error occured or unsupported URL content
	 * @throws IllegalStateException if task has not completed execution
	 */
	public String getContentType() {
		if (!isDone()) {
			throw new IllegalStateException("task has not completed");
		}
		return contentType;
	}

	@Override
	public void processResult(DomainFile domainFile, URL url, TaskMonitor monitor) {
		contentType = domainFile.getContentType();
	}
}
