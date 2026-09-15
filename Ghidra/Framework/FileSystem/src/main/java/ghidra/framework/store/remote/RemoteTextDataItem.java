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
package ghidra.framework.store.remote;

import java.io.File;
import java.io.IOException;

import javax.help.UnsupportedOperationException;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.TextDataItem;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RemoteTextDataItem extends RemoteFolderItem implements TextDataItem {

	RemoteTextDataItem(RepositoryAdapter repository, RepositoryItem item) {
		super(repository, item);
	}

	@Override
	public long length() throws IOException {
		return 0;
	}

	@Override
	public boolean hasCheckouts() throws IOException {
		return false;
	}

	@Override
	public boolean canRecover() {
		return false;
	}

	@Override
	public boolean isCheckinActive() throws IOException {
		return false;
	}

	@Override
	public void updateCheckoutVersion(long checkoutId, int checkoutVersion, String user)
			throws IOException {
		throw new UnsupportedOperationException("Text data files do not support checkin");
	}

	@Override
	public void output(File outputFile, int ver, TaskMonitor monitor)
			throws IOException, CancelledException {
		throw new UnsupportedOperationException("Text data files do not support serial output");
	}

	@Override
	public String getTextData() {
		return textData;
	}

}
