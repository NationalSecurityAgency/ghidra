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
package pdb.symbolserver;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Options that control how Pdb files are searched for on a SymbolServer.
 */
public enum FindOption {
	/**
	 * Allow connections to remote symbol servers
	 */
	ALLOW_REMOTE,
	/**
	 * Only return the first result 
	 */
	ONLY_FIRST_RESULT,
	/**
	 * Match any Pdb with the same name, regardless of GUID / signature id / age.
	 * (implies ANY_AGE)  
	 */
	ANY_ID,
	/**
	 * Match any Pdb with the same name and ID, regardless of age. 
	 */
	ANY_AGE;

	/**
	 * Static constant empty set of no FindOptions.
	 */
	public static final Set<FindOption> NO_OPTIONS = Set.of();

	/**
	 * Create a container of FindOptions.
	 * 
	 * @param findOptions varargs list of FindOption enum values
	 * @return set of the specified FindOptions
	 */
	public static Set<FindOption> of(FindOption... findOptions) {
		EnumSet<FindOption> result = EnumSet.noneOf(FindOption.class);
		result.addAll(List.of(findOptions));
		return result;
	}

}
