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
package ghidra.app.plugin.core.debug.gui.timeline;

import com.google.common.collect.Range;

import ghidra.trace.model.Trace;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.thread.TraceThread;

// TODO: Create an interface for time-bound objects
// Then either:
// 1) The appropriate trace and/or target objects can implement them
// 2) We create the necessary wrappers, one for trace threads, and another for TTD target objects
public class TraceObject implements TraceThread {

	private Object object;
	private Trace trace;
	private String name;
	private Long creationTick;
	private Long destructionTick;
	private Range<Long> lifespan;
	private String comment;
	private long key = 0L;
	private boolean isThread = false;

	public TraceObject(Trace currentTrace) {
		this.trace = currentTrace;
		this.object = null;
		creationTick = 0L;
		destructionTick = Long.MAX_VALUE;
		lifespan = Range.atLeast(creationTick);
	}

	public TraceObject(TraceThread thread) {
		this.trace = thread.getTrace();
		this.object = thread;
		name = thread.getName();
		creationTick = thread.getCreationSnap();
		destructionTick = thread.getDestructionSnap();
		lifespan = thread.getLifespan();
		key = thread.getKey();
		comment = thread.getComment();
		isThread = true;
	}

	public TraceObject(TraceModule module) {
		this.trace = module.getTrace();
		this.object = module;
		name = module.getName();
		creationTick = module.getLoadedSnap();
		destructionTick = module.getUnloadedSnap();
		lifespan = module.getLifespan();
		comment = module.toString();
	}

	public Object getObject() {
		return object;
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public long getKey() {
		return key;
	}

	@Override
	public String getPath() {
		return name; // TODO
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void setName(String name) {
		this.name = name;
	}

	@Override
	public void setCreationSnap(long creationTick) {
		this.creationTick = creationTick;
		lifespan = Range.closed(creationTick, destructionTick);
	}

	@Override
	public long getCreationSnap() {
		return creationTick;
	}

	@Override
	public void setDestructionSnap(long destructionTick) {
		this.destructionTick = destructionTick;
		lifespan = Range.closed(creationTick, destructionTick);
	}

	@Override
	public long getDestructionSnap() {
		return destructionTick;
	}

	@Override
	public void setLifespan(Range<Long> lifespan) {
		this.lifespan = lifespan;
	}

	@Override
	public Range<Long> getLifespan() {
		return lifespan;
	}

	@Override
	public void setComment(String comment) {
		this.comment = comment;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public void delete() {
		// TODO Auto-generated method stub

	}

	public boolean isThread() {
		return isThread;
	}

}
