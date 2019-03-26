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
package util.demangler;

public class GenericDemangledType {
	private GenericDemangledType namespace;
	private String name;
	private GenericDemangledTemplate template;
	private boolean isConst;
	private boolean isVolatile;

	public GenericDemangledType(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
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

	public GenericDemangledType getNamespace() {
		return namespace;
	}

	public void setNamespace(GenericDemangledType namespace) {
		if (this == namespace) {
			throw new IllegalArgumentException("Attempt to set this.namespace == this!");
		}
		this.namespace = namespace;
	}

	public GenericDemangledTemplate getTemplate() {
		return template;
	}

	public void setTemplate(GenericDemangledTemplate template) {
		this.template = template;
	}

	public String toSignature() {
		StringBuffer buffer = new StringBuffer();
		if (namespace != null) {
			buffer.append(namespace.toNamespace());
		}
		buffer.append(name);
		if (template != null) {
			buffer.append(template.toTemplate());
		}
		return buffer.toString();
	}

	public String toNamespace() {
		StringBuffer buffer = new StringBuffer();
		if (namespace != null) {
			buffer.append(namespace.toNamespace());
		}
		buffer.append(name);
		if (template != null) {
			buffer.append(template.toTemplate());
		}
		buffer.append("::");
		return buffer.toString();
	}

	@Override
	public String toString() {
		return toSignature();
	}
}
