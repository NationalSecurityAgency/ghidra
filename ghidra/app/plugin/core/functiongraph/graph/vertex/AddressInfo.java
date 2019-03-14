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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import ghidra.program.model.address.AddressSetView;

import org.jdom.Element;

public class AddressInfo {

	private static final String START_ADDRESS = "START_ADDRESS";
	private static final String END_ADDRESS = "END_ADDRESS";
	static final String VERTEX_ADDRESS_INFO_ELEMENT_NAME = "VERTEX_ADDRESS_INFO";

	String addressRangeStart;
	String addressRangeEnd;

	AddressInfo(FGVertex vertex) {
		if (vertex == null) {
			throw new NullPointerException("Vertex cannot be null");
		}

		AddressSetView addresses = vertex.getAddresses();
		this.addressRangeStart = addresses.getMinAddress().toString();
		this.addressRangeEnd = addresses.getMaxAddress().toString();
	}

	AddressInfo(Element element) {
		addressRangeStart = element.getAttributeValue(START_ADDRESS);
		addressRangeEnd = element.getAttributeValue(END_ADDRESS);

		if (addressRangeStart == null) {
			throw new NullPointerException("Error reading XML for " + getClass().getName());
		}

		if (addressRangeEnd == null) {
			throw new NullPointerException("Error reading XML for " + getClass().getName());
		}
	}

	void write(Element parent) {
		Element element = new Element(VERTEX_ADDRESS_INFO_ELEMENT_NAME);
		element.setAttribute(START_ADDRESS, addressRangeStart);
		element.setAttribute(END_ADDRESS, addressRangeEnd);
		parent.addContent(element);
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + "[start=" + addressRangeStart + ", end=" +
			addressRangeEnd + "]";
	}
}
