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
package ghidra.bitpatterns.info;

import java.math.BigInteger;

import org.jdom.Element;

/**
 * class for representing the values a specific context register assumes within a function body. 
 */
public class ContextRegisterInfo {

	static final String XML_ELEMENT_NAME = "ContextRegisterInfo";

	String contextRegister;//the context register
	BigInteger value;//the value it assumes

	/**
	 * Default constructor (used by XMLEncoder)
	 */
	public ContextRegisterInfo() {
	}

	/**
	 * Creates a {@link ContextRegisterInfo} object for a specified context register
	 * @param contextRegister
	 */
	public ContextRegisterInfo(String contextRegister) {
		this.contextRegister = contextRegister;
	}

	/**
	 * Returns the context register associated with this {@link ContextRegisterInfo} object
	 * @return
	 */
	public String getContextRegister() {
		return contextRegister;
	}

	/**
	 * Sets the context register associated with this {@link ContextRegisterInfo} object
	 * @param contextRegister
	 */
	public void setContextRegister(String contextRegister) {
		this.contextRegister = contextRegister;
	}

	/**
	 * Sets the value associated with this {@link ContextRegisterInfo} object
	 * @param value
	 */
	public void setValue(BigInteger value) {
		this.value = value;

	}

	/**
	 * Returns the value associated with this {@link ContextRegisterInfo} object as a 
	 * {@link String}.
	 * @return
	 */
	public BigInteger getValue() {
		return value;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(contextRegister);
		sb.append(" ");
		sb.append(value);
		return sb.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ContextRegisterInfo other = (ContextRegisterInfo) obj;
		if (!contextRegister.equals(other.getContextRegister())) {
			return false;
		}
		if (value == null) {
			return (other.getValue() == null);
		}
		if (other.getValue() == null) {
			//in this case we know that value != null
			return false;
		}
		return value.equals(other.getValue());
	}

	@Override
	public int hashCode() {
		int hashCode = 17;
		hashCode = 31 * hashCode + contextRegister.hashCode();
		hashCode = 31 * hashCode + value.hashCode();
		return hashCode;
	}

	/**
	 * Creates a {@link ContextRegisterInfo} object using data in the supplied XML node.
	 * 
	 * @param ele xml Element
	 * @return new {@link ContextRegisterInfo} object, never null
	 */
	public static ContextRegisterInfo fromXml(Element ele) {

		String contextRegister = ele.getAttributeValue("contextRegister");
		String value = ele.getAttributeValue("value");

		ContextRegisterInfo result = new ContextRegisterInfo();
		result.setContextRegister(contextRegister);
		result.setValue(value != null ? new BigInteger(value) : null);

		return result;
	}

	/**
	 * Converts this object into XML
	 * 
	 * @return new jdom Element
	 */
	public Element toXml() {

		Element e = new Element(XML_ELEMENT_NAME);
		e.setAttribute("contextRegister", contextRegister);
		if (value != null) {
			e.setAttribute("value", value.toString());
		}

		return e;
	}
}
