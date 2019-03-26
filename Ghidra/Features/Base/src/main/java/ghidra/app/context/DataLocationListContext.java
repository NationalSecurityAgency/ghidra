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
package ghidra.app.context;

import java.util.List;
import java.util.function.Predicate;

import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * Context mix-in interface that ActionContexts can implement if they can provide a list of
 * {@link Data} object's {@link ProgramLocation}'s.
 */
public interface DataLocationListContext {

	/**
	 * Returns the number of {@link Data} objects for the current action context.
	 * @return  the number of {@link Data} objects for the current action context.
	 */
	int getCount();

	/**
	 * Returns a list of the locations of the current {@link Data} objects in the current action context.
	 * @return a list of the locations of the current {@link Data} objects in the current action context.
	 */
	List<ProgramLocation> getDataLocationList();

	/**
	 * Returns a list of the locations of the current {@link Data} objects in the current action context that pass the given filter.
	 * <P>
	 * @param filter a filter to apply to the current context's Data list, <code>null</code>
	 * implies all elements match.
	 * @return  a list of the locations of the current {@link Data} objects in the current action context that pass the given filter.
	 */
	List<ProgramLocation> getDataLocationList(Predicate<Data> filter);

	/**
	 * Returns the program for the current action context.
	 * @return  the program for the current action context.
	 */
	Program getProgram();

}
