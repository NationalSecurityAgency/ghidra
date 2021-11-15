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
package ghidra.app.util.bin.format.dwarf4.external;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

import ghidra.program.model.listing.Program;

/**
 * List of {@link SearchLocation} types that can be saved / restored from a configuration string. 
 */
public class SearchLocationRegistry {
	public static SearchLocationRegistry getInstance() {
		return instance;
	}

	private static final SearchLocationRegistry instance = new SearchLocationRegistry(true);

	private List<SearchLocationCreationInfo> searchLocCreators = new ArrayList<>();

	/**
	 * Creates a new registry, optionally registering the default SearchLocations.
	 * 
	 * @param registerDefault boolean flag, if true register the built-in {@link SearchLocation}s
	 */
	public SearchLocationRegistry(boolean registerDefault) {
		if (registerDefault) {
			register(LocalDirectorySearchLocation::isLocalDirSearchLoc,
				LocalDirectorySearchLocation::create);
			register(BuildIdSearchLocation::isBuildIdSearchLocation, BuildIdSearchLocation::create);
			register(SameDirSearchLocation::isSameDirSearchLocation, SameDirSearchLocation::create);
		}
	}

	/**
	 * Adds a {@link SearchLocation} to this registry.
	 * 
	 * @param testFunc a {@link Predicate} that tests a location string, returning true if the
	 * string specifies the SearchLocation in question
	 * @param createFunc a {@link SearchLocationCreator} that will create a new {@link SearchLocation}
	 * instance given a location string and a {@link SearchLocationCreatorContext context}
	 */
	public void register(Predicate<String> testFunc, SearchLocationCreator createFunc) {
		searchLocCreators.add(new SearchLocationCreationInfo(testFunc, createFunc));
	}

	/**
	 * Creates a new {@link SearchLocationCreatorContext context}.
	 * 
	 * @param program {@link Program}
	 * @return new {@link SearchLocationCreatorContext}
	 */
	public SearchLocationCreatorContext newContext(Program program) {
		return new SearchLocationCreatorContext(this, program);
	}

	/**
	 * Creates a {@link SearchLocation} using the provided location string.
	 * 
	 * @param locString location string (previously returned by {@link SearchLocation#getName()}
	 * @param context a {@link SearchLocationCreatorContext context}
	 * @return new {@link SearchLocation} instance, or null if there are no registered matching
	 * SearchLocations
	 */
	public SearchLocation createSearchLocation(String locString,
			SearchLocationCreatorContext context) {
		for (SearchLocationCreationInfo slci : searchLocCreators) {
			if (slci.testFunc.test(locString)) {
				return slci.createFunc.create(locString, context);
			}
		}
		return null;
	}

	public interface SearchLocationCreator {
		/**
		 * Creates a new {@link SearchLocation} instance using the provided location string.
		 * 
		 * @param locString location string, previously returned by {@link SearchLocation#getName()}
		 * @param context {@link SearchLocationCreatorContext context}
		 * @return new {@link SearchLocation}
		 */
		SearchLocation create(String locString, SearchLocationCreatorContext context);
	}

	private static class SearchLocationCreationInfo {
		Predicate<String> testFunc;
		SearchLocationCreator createFunc;

		SearchLocationCreationInfo(Predicate<String> testFunc,
				SearchLocationCreator createFunc) {
			this.testFunc = testFunc;
			this.createFunc = createFunc;
		}

	}
}
