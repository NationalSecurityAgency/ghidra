/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import org.xml.sax.Locator;

public interface XmlTracer {
	/**
	 * The trace callback.  Please be quick.
	 * @param locator locator, or null if not available (note: locator information may be inaccurate!)
	 * @param traceMessage the trace message
	 * @param throwableIfAvailable an exception if we're encountering one (or null)
	 */
	public void trace(Locator locator, String traceMessage, Throwable throwableIfAvailable);
}
