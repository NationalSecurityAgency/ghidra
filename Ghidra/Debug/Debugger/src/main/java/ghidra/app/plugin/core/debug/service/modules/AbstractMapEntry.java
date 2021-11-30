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
package ghidra.app.plugin.core.debug.service.modules;

import java.util.Objects;

import ghidra.app.services.MapEntry;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.*;

public abstract class AbstractMapEntry<T, P> implements MapEntry<T, P> {
	protected final Trace fromTrace;
	protected final T fromObject;
	protected Program toProgram;
	protected P toObject;

	public AbstractMapEntry(Trace fromTrace, T fromObject, Program toProgram, P toObject) {
		this.fromTrace = fromTrace;
		this.fromObject = fromObject;
		this.toProgram = toProgram;
		this.toObject = toObject;
	}

	@Override
	public boolean equals(Object obj) {
		// TODO: I guess comparing only the "from" object is sufficient....
		if (!(obj instanceof AbstractMapEntry<?, ?>)) {
			return false;
		}
		AbstractMapEntry<?, ?> that = (AbstractMapEntry<?, ?>) obj;
		return this.fromObject == that.fromObject;
	}

	@Override
	public int hashCode() {
		return Objects.hash(fromObject);
	}

	@Override
	public Trace getFromTrace() {
		return fromTrace;
	}

	@Override
	public T getFromObject() {
		return fromObject;
	}

	@Override
	public TraceLocation getFromTraceLocation() {
		return new DefaultTraceLocation(fromTrace, null, getFromLifespan(),
			getFromRange().getMinAddress());
	}

	protected void setToObject(Program toProgram, P toObject) {
		this.toProgram = toProgram;
		this.toObject = toObject;
	}

	@Override
	public Program getToProgram() {
		return toProgram;
	}

	@Override
	public P getToObject() {
		return toObject;
	}

	@Override
	public ProgramLocation getToProgramLocation() {
		return new ProgramLocation(toProgram, getToRange().getMinAddress());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote Ideally the "from" and "to" objects have exactly the same length. If they don't,
	 *           take the minimum.
	 */
	@Override
	public long getMappingLength() {
		return Math.min(getFromRange().getLength(), getToRange().getLength());
	}
}
