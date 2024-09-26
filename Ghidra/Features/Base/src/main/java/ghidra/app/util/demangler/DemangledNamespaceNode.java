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

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.symbol.Namespace;

/**
 * Represents a plain namespace node that is not a type or method
 */
public class DemangledNamespaceNode implements Demangled {

	// The intention is for this to be as refined a part of a larger mangled string as possible,
	//  but it is up to the user to know if they can pass that more refined string or if they
	//  just have to pass a bigger piece.
	protected String mangled;
	private String originalDemangled;
	private String demangledName;
	private String name; // 'safe' name

	protected Demangled namespace;

	/**
	 * Constructor
	 * @param mangled as a refined a piece of the (larger) original mangled stream as the user
	 * can provide, though many times the larger piece is all that the user can provide
	 * @param originalDemangled the original demangled string to match mangled string with the
	 * same caveats
	 * @param name the name of the namespace node
	 */
	public DemangledNamespaceNode(String mangled, String originalDemangled, String name) {
		this.mangled = mangled;
		this.originalDemangled = originalDemangled;
		setName(name);
	}

	@Override
	public void setName(String name) {
		if (StringUtils.isBlank(name)) {
			throw new IllegalArgumentException("Name cannot be blank");
		}
		demangledName = name;
		this.name = DemanglerUtil.stripSuperfluousSignatureSpaces(name).replace(' ', '_');
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getMangledString() {
		return mangled;
	}

	@Override
	public String getOriginalDemangled() {
		return originalDemangled;
	}

	@Override
	public String getDemangledName() {
		return demangledName;
	}

	@Override
	public void setNamespace(Demangled ns) {
		namespace = ns;
	}

	@Override
	public Demangled getNamespace() {
		return namespace;
	}

	@Override
	public String getNamespaceString() {
		return getName(true);
	}

	@Override
	public String getNamespaceName() {
		return name;
	}

	@Override
	public String getSignature() {
		return getNamespaceName();
	}

	private String getName(boolean includeNamespace) {
		StringBuilder builder = new StringBuilder();
		if (includeNamespace && namespace != null) {
			builder.append(namespace.getNamespaceString());
			builder.append(Namespace.DELIMITER);
		}
		builder.append(demangledName);
		return builder.toString();
	}

	@Override
	public String toString() {
		return getNamespaceString();
	}

}
