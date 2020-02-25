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

import ghidra.program.model.symbol.Namespace;

// TODO maybe rename this to DemangledNamespace
public class DemangledType implements Demangled {
	private String demangledName;
	private String name;
	protected String mangled; // the original mangled string
	protected Demangled namespace;
	protected DemangledTemplate template;
	private boolean isConst;
	private boolean isVolatile;

	public DemangledType(String name) {
		setName(name);
	}

	/** 
	 * Returns the unmodified demangled name of this object.
	 * This name may contain whitespace and other characters not
	 * supported for symbol or data type creation.  See {@link #getName()} 
	 * for the same name modified for use within Ghidra.
	 * @return name of this DemangledObject
	 */
	public String getDemangledName() {
		return demangledName;
	}

	/**
	 * Get the name of this type.
	 * NOTE: unsupported symbol characters, like whitespace, will be
	 * converted to an underscore.
	 * @return name of this DemangledType suitable for namespace creation.
	 */
	@Override
	public String getName() {
		return name;
	}

	/**
	 * Sets the name of the demangled type object.
	 * @param name the new name
	 */
	public void setName(String name) {
		demangledName = name;
		this.name = name;
		if (name != null) {
			// use safe name and omit common spaces where they are unwanted in names
			this.name = DemanglerUtil.stripSuperfluousSignatureSpaces(name).replace(' ', '_');
		}
	}

	@Override
	public void setMangledString(String mangled) {
		this.mangled = mangled;
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

	public String toSignature() {
		return toNamespaceString();
	}

	@Override
	public String toNamespaceString() {
		return getName(true);
	}

	private String getName(boolean includeNamespace) {
		StringBuilder buffer = new StringBuilder();
		if (includeNamespace && namespace != null) {
			buffer.append(namespace.toNamespaceString());
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
	public String toNamespaceName() {
		return getName(false);
	}

	@Override
	public String toString() {
		return toNamespaceString();
	}
}
