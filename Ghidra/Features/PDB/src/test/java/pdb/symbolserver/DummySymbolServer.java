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
package pdb.symbolserver;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;

import ghidra.util.task.TaskMonitor;

/**
 * A "remote" symbol server that answers affirmatively for any query.
 */
public class DummySymbolServer implements SymbolServer {

	private final byte[] dummyPayload;
	private final boolean returnCompressedFilenames;

	public DummySymbolServer(String dummyPayload) {
		this(dummyPayload.getBytes(), false);
	}

	public DummySymbolServer(byte[] dummyPayload, boolean returnCompressedFilenames) {
		this.dummyPayload = dummyPayload;
		this.returnCompressedFilenames = returnCompressedFilenames;
	}

	@Override
	public String getName() {
		return "dummy";
	}

	@Override
	public boolean isValid(TaskMonitor monitor) {
		return true;
	}

	@Override
	public boolean exists(String filename, TaskMonitor monitor) {
		return true;
	}

	@Override
	public List<SymbolFileLocation> find(SymbolFileInfo pdbInfo, Set<FindOption> findOptions,
			TaskMonitor monitor) {
		String name = pdbInfo.getName();
		if (returnCompressedFilenames) {
			name = name.substring(0, name.length() - 1) + "_";
		}
		SymbolFileLocation symLoc = new SymbolFileLocation(name, this, pdbInfo);
		return List.of(symLoc);
	}

	@Override
	public SymbolServerInputStream getFileStream(String filename, TaskMonitor monitor)
			throws IOException {
		return new SymbolServerInputStream(new ByteArrayInputStream(dummyPayload),
			dummyPayload.length);
	}

	@Override
	public String getFileLocation(String filename) {
		return "dummy-" + filename;
	}

	@Override
	public boolean isLocal() {
		return false;
	}

}
