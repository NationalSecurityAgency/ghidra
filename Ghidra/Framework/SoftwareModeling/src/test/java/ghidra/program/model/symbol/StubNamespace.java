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
package ghidra.program.model.symbol;

import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class StubNamespace implements Namespace {

	private Namespace parent;
	private String name;

	public StubNamespace(String name, Namespace parent) {
		this.name = name;
		this.parent = parent;
	}

	@Override
	public Symbol getSymbol() {
		return new StubSymbol(name);
	}

	@Override
	public boolean isExternal() {
		return false;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getName(boolean includeNamespacePath) {
		if (!includeNamespacePath || parent == null) {
			return name;
		}
		return parent.getName(true) + Namespace.DELIMITER + name;
	}

	@Override
	public long getID() {
		return 1;
	}

	@Override
	public Namespace getParentNamespace() {
		return parent;
	}

	@Override
	public AddressSetView getBody() {
		return null;
	}

	@Override
	public void setParentNamespace(Namespace parentNamespace)
			throws DuplicateNameException, InvalidInputException, CircularDependencyException {
		// ignore
	}

}
