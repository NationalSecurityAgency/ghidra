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
package ghidra.dbg.testutil;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathPredicates;

public interface TestDebuggerModelProvider {
	interface ModelHost extends AutoCloseable {
		interface WithoutThreadValidation extends AutoCloseable {
		}

		Map<String, Object> getFactoryOptions();

		ModelHost build() throws Throwable;

		DebuggerObjectModel buildModel(Map<String, Object> options) throws Throwable;

		DebuggerObjectModel getModel();

		void validateCompletionThread();

		TargetObject getRoot() throws Throwable;

		List<String> getBogusPath();

		boolean hasDetachableProcesses();

		boolean hasInterpreter();

		boolean hasInterruptibleProcesses();

		boolean hasKillableProcesses();

		boolean hasResumableProcesses();

		boolean hasAttachableContainer();

		boolean hasAttacher();

		boolean hasEventScope();

		boolean hasLauncher();

		boolean hasProcessContainer();

		WithoutThreadValidation withoutThreadValidation();

		<T extends TargetObject> T find(Class<T> cls, List<String> seedPath) throws Throwable;

		/**
		 * Use the schema to find the appropriate path, substituting the given index for a wildcard
		 * at most once, then get or wait for that object
		 * 
		 * @param <T> the type of object
		 * @param cls the class giving the type
		 * @param index the index when needed
		 * @param seedPath the seed path for the search. The result will be a successor
		 * @return the found object, or {@code null} if the schema does not give it
		 * @throws Throwable if anything goes wrong
		 */
		<T extends TargetObject> T findWithIndex(Class<T> cls, String index, List<String> seedPath)
				throws Throwable;

		<T extends TargetObject> T findAny(Class<T> cls, List<String> seedPath) throws Throwable;

		<T extends TargetObject> Map<List<String>, T> findAll(Class<T> cls, List<String> seedPath,
				boolean atLeastOne) throws Throwable;

		<T extends TargetObject> Map<List<String>, T> findAll(Class<T> cls, List<String> seedPath,
				Function<PathPredicates, PathPredicates> adjustPredicates, boolean atLeastOne)
				throws Throwable;

		TargetObject findContainer(Class<? extends TargetObject> cls, List<String> seedPath)
				throws Throwable;

		<T extends TargetObject> T suitable(Class<T> cls, List<String> seedPath) throws Throwable;

		TargetObjectAddedWaiter getAddedWaiter();
	}

	ModelHost modelHost() throws Throwable;
}
