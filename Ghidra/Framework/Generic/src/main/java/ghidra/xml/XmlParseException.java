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
package ghidra.xml;

/**
 * Exception that gets thrown if there is a problem parsing XML.
 * <p>
 * NOTE: We used to use {@link javax.management.modelmbean.XMLParseException}
 * but dealing with that class was annoying in Java 9.
 */
public class XmlParseException extends Exception {

	public XmlParseException(String message) {
		super(message);
	}

	public XmlParseException(String message, Throwable t) {
		super(message, t);
	}
}
