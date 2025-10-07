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
package ghidra.app.util.bin.format.dwarf.external;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import ghidra.program.model.listing.Program;

/**
 * List of {@link DebugInfoProvider} types that can be saved / restored from a configuration string. 
 */
public class DebugInfoProviderRegistry {
	public static DebugInfoProviderRegistry getInstance() {
		return instance;
	}

	private static final DebugInfoProviderRegistry instance = new DebugInfoProviderRegistry();

	private List<DebugInfoProviderCreationInfo> creators = new ArrayList<>();

	/**
	 * Creates a new registry
	 */
	public DebugInfoProviderRegistry() {
		register(DisabledDebugInfoProvider::matches, DisabledDebugInfoProvider::create);
		register(LocalDirDebugLinkProvider::matches, LocalDirDebugLinkProvider::create);
		register(SameDirDebugInfoProvider::matches, SameDirDebugInfoProvider::create);
		register(BuildIdDebugFileProvider::matches, BuildIdDebugFileProvider::create);
		register(LocalDirDebugInfoDProvider::matches, LocalDirDebugInfoDProvider::create);
		register(HttpDebugInfoDProvider::matches, HttpDebugInfoDProvider::create);
	}

	/**
	 * Adds a {@link DebugFileProvider} to this registry.
	 * 
	 * @param testFunc a {@link Predicate} that tests a name string, returning true if the
	 * string specifies the provider in question
	 * @param createFunc a {@link DebugInfoProviderCreator} that will create a new 
	 * {@link DebugFileProvider} instance given a name string and a
	 * {@link DebugInfoProviderCreatorContext context}
	 */
	public void register(Predicate<String> testFunc, DebugInfoProviderCreator createFunc) {
		creators.add(new DebugInfoProviderCreationInfo(testFunc, createFunc));
	}

	/**
	 * Creates a new {@link DebugInfoProviderCreatorContext context}.
	 * 
	 * @param program {@link Program}
	 * @return new {@link DebugInfoProviderCreatorContext}
	 */
	public DebugInfoProviderCreatorContext newContext(Program program) {
		return new DebugInfoProviderCreatorContext(this, program);
	}

	/**
	 * Creates a {@link DebugFileProvider} using the specified name string.
	 * 
	 * @param name string previously returned by {@link DebugFileProvider#getName()}
	 * @param context a {@link DebugInfoProviderCreatorContext context}
	 * @return new {@link DebugFileProvider} instance, or null if there are no registered matching
	 * providers
	 */
	public DebugInfoProvider create(String name, DebugInfoProviderCreatorContext context) {
		for (DebugInfoProviderCreationInfo slci : creators) {
			if (slci.testFunc.test(name)) {
				return slci.createFunc.create(name, context);
			}
		}
		return null;
	}

	private interface DebugInfoProviderCreator {
		/**
		 * Creates a new {@link DebugFileProvider} instance using the provided name string.
		 * 
		 * @param name string, previously returned by {@link DebugFileProvider#getName()}
		 * @param context {@link DebugInfoProviderCreatorContext context}
		 * @return new {@link DebugFileProvider}
		 */
		DebugInfoProvider create(String name, DebugInfoProviderCreatorContext context);
	}

	private static class DebugInfoProviderCreationInfo {
		Predicate<String> testFunc;
		DebugInfoProviderCreator createFunc;

		DebugInfoProviderCreationInfo(Predicate<String> testFunc,
				DebugInfoProviderCreator createFunc) {
			this.testFunc = testFunc;
			this.createFunc = createFunc;
		}

	}
}
