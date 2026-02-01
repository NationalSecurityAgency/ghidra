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

import java.util.Set;

import ghidra.app.plugin.core.debug.client.tracermi.RmiClient.RequestResult;
import ghidra.rmi.trace.TraceRmi.Resolution;
import ghidra.rmi.trace.TraceRmi.ValueKinds;
import ghidra.trace.model.Lifespan;

public class RmiTraceObject {

	private final RmiTrace trace;
	private final String path;
	private volatile Long id;

	public RmiTraceObject(RmiTrace trace, String path) {
		this.trace = trace;
		this.path = path;
	}

	RmiTraceObject(RmiTrace trace, String path, RequestResult result) {
		this.trace = trace;
		this.path = path;
		result.thenAccept(id -> this.id = (Long) id);
	}

	public RmiTraceObject(RmiTrace trace, Long id, String path) {
		this.trace = trace;
		this.id = id;
		this.path = path;
	}

	public static RmiTraceObject fromId(RmiTrace trace, long id) {
		return new RmiTraceObject(trace, id, null);
	}

	public static RmiTraceObject fromPath(RmiTrace trace, String path) {
		return new RmiTraceObject(trace, null, path);
	}

	public Lifespan insert(long snap, Resolution resolution) {
		if (resolution == null) {
			resolution = Resolution.CR_ADJUST;
		}
		Lifespan span = Lifespan.nowOn(snap);
		if (id != null) {
			trace.client.insertObject(trace.getId(), id, span, resolution);
		}
		else {
			trace.client.insertObject(trace.getId(), path, span, resolution);
		}
		return span;
	}

	public Lifespan remove(long snap, boolean tree) {
		Lifespan span = Lifespan.nowOn(snap);
		if (id != null) {
			trace.client.removeObject(trace.getId(), id, span, tree);
		}
		else {
			trace.client.removeObject(trace.getId(), path, span, tree);
		}
		return span;
	}

	public void setValue(String key, Object value, long snap, String resolution) {
		Lifespan span = Lifespan.nowOn(snap);
		trace.client.setValue(trace.getId(), path, span, key, value, resolution);
	}

	public void retainValues(Set<String> keys, long snap, ValueKinds kinds) {
		Lifespan span = Lifespan.nowOn(snap);
		trace.client.retainValues(trace.getId(), path, span, kinds, keys);
	}

	public void activate() {
		trace.client.activate(trace.getId(), path);
	}

	public String getPath() {
		return path;
	}

}
