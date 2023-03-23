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
package ghidra.trace.model.time.schedule;

import java.util.List;

import ghidra.program.model.lang.Language;

public abstract class AbstractStep implements Step {
	protected final long threadKey;
	protected long tickCount;

	protected AbstractStep(long threadKey, long tickCount) {
		if (tickCount < 0) {
			throw new IllegalArgumentException("Cannot step a negative number");
		}
		this.threadKey = threadKey;
		this.tickCount = tickCount;
	}

	/**
	 * Return the step portion of {@link #toString()}
	 * 
	 * @return the string
	 */
	protected abstract String toStringStepPart();

	@Override
	public String toString() {
		if (threadKey == -1) {
			return toStringStepPart();
		}
		return String.format("t%d-", threadKey) + toStringStepPart();
	}

	@Override
	public boolean isNop() {
		return tickCount == 0;
	}

	@Override
	public long getThreadKey() {
		return threadKey;
	}

	@Override
	public long getTickCount() {
		return tickCount;
	}

	@Override
	public long getPatchCount() {
		return 0;
	}

	@Override
	public abstract AbstractStep clone();

	/**
	 * Add to the count of this step
	 * 
	 * @param steps the count to add
	 */
	public void advance(long steps) {
		if (steps < 0) {
			throw new IllegalArgumentException("Cannot advance a negative number");
		}
		long newCount = tickCount + steps;
		if (newCount < 0) {
			throw new IllegalArgumentException("Total step count exceeds LONG_MAX");
		}
		this.tickCount = newCount;
	}

	@Override
	public long rewind(long steps) {
		if (steps < 0) {
			throw new IllegalArgumentException("Cannot rewind a negative number");
		}
		long diff = this.tickCount - steps;
		this.tickCount = Long.max(0, diff);
		return -diff;
	}

	@Override
	public boolean isCompatible(Step step) {
		if (!(step.getClass() == this.getClass())) {
			return false;
		}
		AbstractStep as = (AbstractStep) step;
		return this.threadKey == as.threadKey || as.threadKey == -1;
	}

	@Override
	public void addTo(Step step) {
		assert isCompatible(step);
		AbstractStep as = (AbstractStep) step;
		advance(as.tickCount);
	}

	@Override
	public int hashCode() {
		return Long.hashCode(threadKey) * 31 + Long.hashCode(tickCount);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj.getClass() != this.getClass()) {
			return false;
		}
		AbstractStep that = (AbstractStep) obj;
		if (this.threadKey != that.threadKey) {
			return false;
		}
		if (this.tickCount != that.tickCount) {
			return false;
		}
		return true;
	}

	@Override
	public CompareResult compareStep(Step step) {
		CompareResult result;

		result = compareStepType(step);
		if (result != CompareResult.EQUALS) {
			return result;
		}

		AbstractStep that = (AbstractStep) step;
		result = CompareResult.unrelated(Long.compare(this.threadKey, that.threadKey));
		if (result != CompareResult.EQUALS) {
			return result;
		}

		result = CompareResult.related(Long.compare(this.tickCount, that.tickCount));
		if (result != CompareResult.EQUALS) {
			return result;
		}

		return CompareResult.EQUALS;
	}

	@Override
	public long coalescePatches(Language language, List<Step> steps) {
		return 0;
	}
}
