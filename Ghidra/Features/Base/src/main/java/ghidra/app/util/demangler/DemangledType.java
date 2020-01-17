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

import java.util.List;

import ghidra.app.util.SymbolPath;
import ghidra.program.model.symbol.Namespace;
import util.demangler.GenericDemangledTemplate;
import util.demangler.GenericDemangledType;

public class DemangledType {
	private String demangledName;
	private String name;
	protected String originalMangled;
	protected DemangledType namespace;
	protected DemangledTemplate template;
	private boolean isConst;
	private boolean isVolatile;

	/**
	 * Takes a {@link DemangledType} with a name that contains namespace elements
	 * (such as Foo::Bar) and breaks it into a hierarchy of types where each type
	 * represents one item in the list of namespace elements.
	 *
	 * @param otherNamespace the type to convert
	 * @return the original type if the name does not represent a namespace; a new type
	 *         that contains a child, that contains a child and so on, representing the
	 *         split-up of the original namespace string.
	 */
	public static DemangledType convertToNamespace(GenericDemangledType otherNamespace) {
		if (otherNamespace == null) {
			return null;
		}

		DemangledType newNamespace = new DemangledType(otherNamespace);
		String demangledName = newNamespace.getName();

		SymbolPath symbolPath = new SymbolPath(demangledName);
		if (symbolPath.getParent() == null) {
			return newNamespace;
		}

		List<String> names = symbolPath.asList();

		DemangledType lastParent = new DemangledType(names.get(0));
		for (int i = 1; i < names.size(); i++) {
			DemangledType child = new DemangledType(names.get(i));
			child.setNamespace(lastParent);
			lastParent = child;
		}

		return lastParent;
	}

	public DemangledType(String name) {
		setName(name);
	}

	DemangledType(GenericDemangledType toCopy) {
		GenericDemangledType otherNamespace = toCopy.getNamespace();

		if (otherNamespace != null) {
			namespace = convertToNamespace(otherNamespace);
		}

		setName(toCopy.getName());
		GenericDemangledTemplate otherTemplate = toCopy.getTemplate();
		if (otherTemplate != null) {
			template = new DemangledTemplate(otherTemplate);
		}
		isConst = toCopy.isConst();
		isVolatile = toCopy.isVolatile();
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

	/**
	 * Sets the original mangled name
	 * @param mangled the original mangled name
	 */
	public void setOriginalMangled(String mangled) {
		this.originalMangled = mangled;
	}

	/**
	 * Gets the original mangled name
	 * @return the original mangled name
	 */
	public String getOriginalMangled() {
		return originalMangled;
	}

	public boolean isConst() {
		return isConst;
	}

	public void setConst() {
		isConst = true;
	}

	public boolean isFunction() {
		return false;
	}

	public boolean isVolatile() {
		return isVolatile;
	}

	public void setVolatile() {
		isVolatile = true;
	}

	public DemangledType getNamespace() {
		return namespace;
	}

	public void setNamespace(DemangledType namespace) {
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
		return toNamespace();
	}

	public String toNamespace() {
		StringBuffer buffer = new StringBuffer();
		if (namespace != null) {
			buffer.append(namespace.toNamespace());
		}
		buffer.append(demangledName);
		if (template != null) {
			buffer.append(template.toTemplate());
		}

		if (buffer.length() == 0) {
			return "";
		}

		buffer.append(Namespace.DELIMITER);
		return buffer.toString();
	}

	@Override
	public String toString() {
		return toNamespace();
	}
}
