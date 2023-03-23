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
package ghidra.trace.model.target;

import ghidra.lifecycle.Transitional;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Lifespan.LifeSet;
import ghidra.trace.model.thread.TraceObjectThread;

/**
 * A common interface for object-based implementations of other trace manager entries, e.g.,
 * {@link TraceObjectThread}.
 */
public interface TraceObjectInterface {
	/**
	 * Get the object backing this implementation
	 * 
	 * @return the object
	 */
	TraceObject getObject();

	/**
	 * Compute the lifespan of this object
	 * 
	 * @return the span of all lifespans
	 */
	@Transitional
	default Lifespan computeSpan() {
		LifeSet life = getObject().getLife();
		if (life.isEmpty()) {
			return null;
		}
		return life.bound();
	}

	@Transitional
	default long computeMinSnap() {
		return computeSpan().lmin();
	}

	@Transitional
	default long computeMaxSnap() {
		return computeSpan().lmax();
	}
}
