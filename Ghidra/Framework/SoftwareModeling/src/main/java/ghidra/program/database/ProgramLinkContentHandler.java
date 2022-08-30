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
package ghidra.program.database;

import java.io.IOException;

import javax.swing.Icon;

import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.URLLinkObject;
import ghidra.framework.model.DomainObject;
import ghidra.framework.store.FileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ProgramLinkContentHandler extends LinkHandler<ProgramDB> {

	public static final String PROGRAM_LINK_CONTENT_TYPE = "ProgramLink";

	@Override
	public long createFile(FileSystem fs, FileSystem userfs, String path, String name,
			DomainObject obj, TaskMonitor monitor)
			throws IOException, InvalidNameException, CancelledException {
		if (!(obj instanceof URLLinkObject)) {
			throw new IOException("Unsupported domain object: " + obj.getClass().getName());
		}
		return createFile((URLLinkObject) obj, PROGRAM_LINK_CONTENT_TYPE, fs, path, name,
			monitor);
	}

	@Override
	public String getContentType() {
		return PROGRAM_LINK_CONTENT_TYPE;
	}

	@Override
	public String getContentTypeDisplayString() {
		return PROGRAM_LINK_CONTENT_TYPE;
	}

	@Override
	public Class<ProgramDB> getDomainObjectClass() {
		// return linked content class
		return ProgramContentHandler.PROGRAM_DOMAIN_OBJECT_CLASS;
	}

	@Override
	public Icon getIcon() {
		return ProgramContentHandler.PROGRAM_ICON;
	}

	@Override
	public String getDefaultToolName() {
		return ProgramContentHandler.PROGRAM_CONTENT_DEFAULT_TOOL;
	}

}
