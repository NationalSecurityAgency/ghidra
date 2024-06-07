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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.collections4.set.AbstractSetDecorator;

import ghidra.app.plugin.assembler.sleigh.util.DbgTimer;

/**
 * A set of possible assembly resolutions for a single SLEIGH constructor
 * 
 * <p>
 * Since the assembler works from the leaves up, it's unclear in what context a given token appears.
 * Thus, every possible encoding is collected and passed upward. As resolution continues, many of
 * the possible encodings are pruned out. When the resolver reaches the root, we end up with every
 * possible encoding (less some prefixes) of an instruction. This object stores the possible
 * encodings, including error records describing the pruned intermediate results.
 */
public class AssemblyResolutionResults extends AbstractSetDecorator<AssemblyResolution> {
	protected static final DbgTimer DBG = AbstractAssemblyTreeResolver.DBG;

	public interface Applicator {
		Iterable<? extends AssemblyResolution> getPatterns(AssemblyResolvedPatterns cur);

		default AssemblyResolvedPatterns setDescription(
				AssemblyResolvedPatterns res, AssemblyResolution from) {
			AssemblyResolvedPatterns temp = res.withDescription(from.getDescription());
			return temp;
		}

		default AssemblyResolvedPatterns setRight(AssemblyResolvedPatterns res,
				AssemblyResolvedPatterns cur) {
			return res.withRight(cur);
		}

		default AssemblyResolvedPatterns combineConstructor(AssemblyResolvedPatterns cur,
				AssemblyResolvedPatterns pat) {
			AssemblyResolvedPatterns combined = cur.combine(pat);
			if (combined == null) {
				return null;
			}
			return setRight(setDescription(combined, pat), cur);
		}

		default AssemblyResolvedPatterns combineBackfill(AssemblyResolvedPatterns cur,
				AssemblyResolvedBackfill bf) {
			AssemblyResolvedPatterns combined = cur.combine(bf);
			return setRight(setDescription(combined, bf), cur);
		}

		default AssemblyResolvedPatterns combine(AssemblyResolvedPatterns cur,
				AssemblyResolution pat) {
			if (pat.isError()) {
				throw new AssertionError();
			}
			if (pat.isBackfill()) {
				return combineBackfill(cur, (AssemblyResolvedBackfill) pat);
			}
			return combineConstructor(cur, (AssemblyResolvedPatterns) pat);
		}

		String describeError(AssemblyResolvedPatterns rc, AssemblyResolution pat);

		default AssemblyResolution finish(AssemblyResolvedPatterns resolved) {
			return resolved;
		}
	}

	protected final Set<AssemblyResolution> resolutions;

	/**
	 * Construct a new (mutable) empty set of resolutions
	 */
	public AssemblyResolutionResults() {
		resolutions = new LinkedHashSet<>();
	}

	protected AssemblyResolutionResults(Set<AssemblyResolution> resolutions) {
		this.resolutions = resolutions;
	}

	@Override
	public boolean add(AssemblyResolution ar) {
		return resolutions.add(ar);
	}

	/**
	 * A synonym for {@link #addAll(Collection)} that accepts only another resolution set
	 * 
	 * @param that the other set
	 */
	public void absorb(AssemblyResolutionResults that) {
		this.resolutions.addAll(that.resolutions);
	}

	@Override
	public boolean addAll(Collection<? extends AssemblyResolution> c) {
		return this.resolutions.addAll(c);
	}

	/**
	 * Get an unmodifiable reference to this set
	 * 
	 * @return the set
	 */
	public Set<AssemblyResolution> getResolutions() {
		return Collections.unmodifiableSet(resolutions);
	}

	@Override
	protected Set<AssemblyResolution> decorated() {
		return getResolutions();
	}

	public boolean remove(AssemblyResolution ar) {
		return this.resolutions.remove(ar);
	}

	protected AssemblyResolutionResults apply(AbstractAssemblyResolutionFactory<?, ?> factory,
			Applicator applicator) {
		AssemblyResolutionResults results = factory.newAssemblyResolutionResults();
		for (AssemblyResolution res : this) {
			if (res.isError()) {
				results.add(res);
				continue;
			}
			AssemblyResolvedPatterns rp = (AssemblyResolvedPatterns) res;
			DBG.println("Current: " + rp.lineToString());
			for (AssemblyResolution ar : applicator.getPatterns(rp)) {
				DBG.println("Pattern: " + ar.lineToString());
				AssemblyResolvedPatterns combined = applicator.combine(rp, ar);
				DBG.println("Combined: " + (combined == null ? "(null)" : combined.lineToString()));
				if (combined == null) {
					results.add(factory.error(applicator.describeError(rp, ar), ar));
					continue;
				}
				results.add(applicator.finish(combined));
			}
		}
		return results;
	}

	protected AssemblyResolutionResults apply(AbstractAssemblyResolutionFactory<?, ?> factory,
			Function<AssemblyResolvedPatterns, AssemblyResolution> function) {
		return stream().map(res -> {
			if (res instanceof AssemblyResolvedBackfill) {
				throw new AssertionError();
			}
			if (res instanceof AssemblyResolvedError err) {
				return err;
			}
			if (res instanceof AssemblyResolvedPatterns rp) {
				return function.apply(rp);
			}
			throw new AssertionError();
		}).collect(Collectors.toCollection(factory::newAssemblyResolutionResults));
	}
}
