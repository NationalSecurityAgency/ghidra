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
package ghidra.app.util.opinion;

import ghidra.program.model.lang.LanguageCompilerSpecPair;

/**
 * Represents a possible way for a {@link Loader} to load something.
 */
public class LoadSpec {

	private Loader loader;
	private long imageBase;
	private LanguageCompilerSpecPair lcs;
	private boolean isPreferred;
	private boolean requiresLanguageCompilerSpec;

	/**
	 * Constructs a {@link LoadSpec} from a manually supplied {@link LanguageCompilerSpecPair}.
	 * 
	 * @param loader This {@link LoadSpec}'s {@link Loader}.
	 * @param imageBase The desired image base address for the load.
	 * @param languageCompilerSpec The language/compiler spec ID.  If this is not needed or not 
	 *   known, use {@link #LoadSpec(Loader, long, boolean)}.
	 * @param isPreferred true if this {@link LoadSpec} is preferred; otherwise, false.
	 */
	public LoadSpec(Loader loader, long imageBase, LanguageCompilerSpecPair languageCompilerSpec,
			boolean isPreferred) {
		this.loader = loader;
		this.imageBase = imageBase;
		this.lcs = languageCompilerSpec;
		this.isPreferred = isPreferred;

		// We internally define a "preferred" language/compiler being null to mean that the 
		// associated Loader doesn't use a language/compiler, and we define a "non-preferred" 
		// language/compiler being null to mean that the Loader does indeed use a language/compiler,
		// but the Loader wasn't able to figure it out on its own.
		this.requiresLanguageCompilerSpec = lcs != null || !isPreferred;
	}

	/**
	 * Constructs a {@link LoadSpec} from a {@link QueryResult}.
	 * 
	 * @param loader This {@link LoadSpec}'s {@link Loader}.
	 * @param imageBase The desired image base address for the load.
	 * @param languageCompilerSpecQueryResult The language/compiler spec ID.
	 */
	public LoadSpec(Loader loader, long imageBase, QueryResult languageCompilerSpecQueryResult) {
		this(loader, imageBase, languageCompilerSpecQueryResult.pair,
			languageCompilerSpecQueryResult.preferred);
	}

	/**
	 * Constructs a {@link LoadSpec} with an unknown language/compiler.  Some {@link Loader}'s do
	 * not require a language/compiler.
	 * 
	 * @param loader This {@link LoadSpec}'s {@link Loader}.
	 * @param imageBase The desired image base address for the load.
	 * @param requiresLanguageCompilerSpec True if this {@link LoadSpec} requires a
	 *   language/compiler; otherwise, false.  If a language/compiler is required, it will have
	 *   to be supplied to the {@link Loader} by some other means, and this {@link LoadSpec} will
	 *   be considered incomplete.
	 * @see #isComplete()
	 */
	public LoadSpec(Loader loader, long imageBase, boolean requiresLanguageCompilerSpec) {
		this(loader, imageBase, null, !requiresLanguageCompilerSpec);
	}

	/**
	 * Gets this {@link LoadSpec}'s {@link Loader}.
	 * 
	 * @return This {@link LoadSpec}'s {@link Loader}.
	 */
	public Loader getLoader() {
		return loader;
	}

	/**
	 * Gets the desired image base to use during the load.
	 * 
	 * @return The desired image base to use during the load.
	 */
	public long getDesiredImageBase() {
		return imageBase;
	}

	/**
	 * Gets this {@link LoadSpec}'s {@link LanguageCompilerSpecPair}.
	 *   
	 * @return This {@link LoadSpec}'s {@link LanguageCompilerSpecPair}.  Could be null if this
	 *   {@link LoadSpec} doesn't need or know the language/compiler.
	 */
	public LanguageCompilerSpecPair getLanguageCompilerSpec() {
		return lcs;
	}

	/**
	 * Gets whether or not this {@link LoadSpec} is a preferred {@link LoadSpec}.
	 * 
	 * @return True if this {@link LoadSpec} is a preferred {@link LoadSpec}; otherwise, false.
	 */
	public boolean isPreferred() {
		return isPreferred;
	}

	/**
	 * Gets whether or not this {@link LoadSpec} requires a language/compiler to load something.
	 * 
	 * @return True if this {@link LoadSpec} requires a language/compiler to load something; 
	 *   otherwise, false.
	 */
	public boolean requiresLanguageCompilerSpec() {
		return requiresLanguageCompilerSpec;
	}

	/**
	 * Gets whether or not this {@link LoadSpec} is complete.  A {@link LoadSpec} is not considered
	 * complete if it requires a language/compiler to load something, but the language/compiler
	 * is currently unknown.
	 * 
	 * @return True if this {@link LoadSpec} is complete; otherwise, false.
	 */
	public boolean isComplete() {
		return !requiresLanguageCompilerSpec || lcs != null;
	}
}
