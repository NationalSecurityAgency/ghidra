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
package ghidra.app.util.demangler;

import java.util.ArrayList;
import java.util.List;

/**
 * An convenience {@link Demangled} object that holds a {@link List} of other 
 * {@link Demangled} objects
 */
public class DemangledList extends ArrayList<Demangled> implements Demangled {

	/**
	 * Creates a {@link DemangledList} and adds the given {@link List} to it
	 * 
	 * @param demangledList The {@link List} of {@link Demangled} objects to add
	 */
	public DemangledList(List<Demangled> demangledList) {
		super(demangledList);
	}

	/**
	 * {@return true if this contains any <code>null</code> elements; otherwise, false}
	 */
	public boolean containsNull() {
		return stream().anyMatch(e -> e == null);
	}

	@Override
	public String getMangledString() {
		return null;
	}

	@Override
	public String getOriginalDemangled() {
		return null;
	}

	@Override
	public String getName() {
		return null;
	}

	@Override
	public void setName(String name) {
		// Nothing to do
	}

	@Override
	public String getDemangledName() {
		return null;
	}

	@Override
	public Demangled getNamespace() {
		return null;
	}

	@Override
	public void setNamespace(Demangled ns) {
		// Nothing to do
	}

	@Override
	public String getNamespaceString() {
		return null;
	}

	@Override
	public String getNamespaceName() {
		return null;
	}

	@Override
	public String getSignature() {
		return null;
	}

}
