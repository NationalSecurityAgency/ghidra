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
package ghidra.app.plugin.core.debug.client.tracermi;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;

import ghidra.app.plugin.core.debug.client.tracermi.RmiClient.RequestResult;

public class RmiBatch implements AutoCloseable {

	private final RmiClient client;
	private volatile int refCount = 0;
	private final List<RequestResult> futures = new ArrayList<>();

	public RmiBatch(RmiClient client) {
		this.client = client;
	}

	public void inc() {
		refCount++;
	}

	public int dec() {
		return --refCount;
	}

	@Override
	public void close() {
		try {
			client.endBatch(this);
		}
		catch (InterruptedException | ExecutionException e) {
			throw new RuntimeException(e);
		}
	}

	public void append(RequestResult f) {
		synchronized (futures) {
			futures.add(f);
		}
	}

	public List<Object> results() throws InterruptedException, ExecutionException {
		List<RequestResult> futures = futures();
		List<Object> results = new ArrayList<>(futures.size());
		for (RequestResult r : futures) {
			results.add(r.get());
		}
		return results;
	}

	public List<RequestResult> futures() {
		synchronized (futures) {
			return List.copyOf(futures);
		}
	}
}
