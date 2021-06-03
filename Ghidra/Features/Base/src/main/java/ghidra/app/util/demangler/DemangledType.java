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
 * Represents a demangled string.  This class is really just a placeholder for demangled 
 * information.  See {@link DemangledObject} for a class that represents software concepts that
 * can be applied to a program.   The {@link DemangledObject} may use instances of this class
 * to compose its internal state for namespace information, return types and parameters.
 */
public class DemangledType implements Demangled {

	protected String mangled; // the original mangled string
	private String originalDemangled;
	private String demangledName;
	private String name; // 'safe' name

	protected Demangled namespace;
	protected DemangledTemplate template;
	private boolean isConst;
	private boolean isVolatile;

	public DemangledType(String mangled, String originaDemangled, String name) {
		this.mangled = mangled;
		this.originalDemangled = originaDemangled;
		setName(name);
	}

	@Override
	public String getDemangledName() {
		return demangledName;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public void setName(String name) {
		if (StringUtils.isBlank(name)) {
			throw new IllegalArgumentException("Name cannot be blank");
		}

		demangledName = name;
		this.name = name;
		if (name != null) {
			// use safe name and omit common spaces where they are unwanted in names
			this.name = DemanglerUtil.stripSuperfluousSignatureSpaces(name).replace(' ', '_');
		}
	}

	@Override
	public String getOriginalDemangled() {
		return originalDemangled;
	}

	@Override
	public String getMangledString() {
		return mangled;
	}

	public boolean isConst() {
		return isConst;
	}

	public void setConst() {
		isConst = true;
	}

	public boolean isVolatile() {
		return isVolatile;
	}

	public void setVolatile() {
		isVolatile = true;
	}

	@Override
	public Demangled getNamespace() {
		return namespace;
	}

	@Override
	public void setNamespace(Demangled namespace) {
		if (this == namespace) {
			throw new IllegalArgumentException("Attempt to set this.namespace == this!");
		}
		this.namespace = namespace;
	}

	public DemangledTemplate getTemplate() {
		return template;
	}

	public void setTemplate(DemangledTemplate template) {
		this.template = template;
	}

	@Override
	public String getSignature() {
		return getNamespaceName();
	}

	@Override
	public String getNamespaceString() {
		return getName(true);
	}

	private String getName(boolean includeNamespace) {
		StringBuilder buffer = new StringBuilder();
		if (includeNamespace && namespace != null) {
			buffer.append(namespace.getNamespaceString());
			buffer.append(Namespace.DELIMITER);
		}

		buffer.append(demangledName);
		if (template != null) {
			buffer.append(template.toTemplate());
		}

		if (buffer.length() == 0) {
			return "";
		}

		return buffer.toString();
	}

	@Override
	public String getNamespaceName() {
		return name;
	}

	@Override
	public String toString() {
		return getNamespaceString();
	}
}
