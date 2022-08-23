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
package ghidra.trace.database.listing;

/**
 * An abstract implementation of a single-type view
 * 
 * @implNote This class cannot be removed. Despite it appearing not to do anything, this class
 *           serves as an upper bound on the views composed by
 *           {@link AbstractComposedDBTraceCodeUnitsView}.
 * @param <T> the implementation type of the units contained in the view
 */
public abstract class AbstractSingleDBTraceCodeUnitsView<T extends DBTraceCodeUnitAdapter>
		extends AbstractBaseDBTraceCodeUnitsView<T> {

	/**
	 * Construct a view
	 * 
	 * @param space the space, bound to an address space
	 */
	public AbstractSingleDBTraceCodeUnitsView(DBTraceCodeSpace space) {
		super(space);
	}
}
