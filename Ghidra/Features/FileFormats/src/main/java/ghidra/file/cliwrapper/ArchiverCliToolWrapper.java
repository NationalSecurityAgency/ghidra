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
package ghidra.file.cliwrapper;

import java.io.*;
import java.util.List;

import ghidra.formats.gfilesystem.fileinfo.FileType;
import ghidra.util.task.TaskMonitor;

/**
 * Functionality that an archiver cli tool can expose
 */
public interface ArchiverCliToolWrapper extends CliToolWrapper {

	record Entry(String name, long size, FileType fileType) {}

	List<Entry> getListing(File archiveFile, TaskMonitor monitor);

	void extract(File archiveFile, Entry entry, OutputStream os, TaskMonitor monitor)
			throws IOException;

}
