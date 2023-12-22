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
package ghidra.app.util.bin.format.golang.structmapping;

import java.io.IOException;

import ghidra.util.exception.CancelledException;

/**
 * A function that decorates a field in a structure mapped class.
 * 
 * @param <T> structure mapped class type
 */
public interface FieldMarkupFunction<T> {

	/**
	 * Decorates the specified field.
	 * 
	 * @param fieldContext information about the field
	 * @param markupSession state and methods to assist marking up the program 
	 * @throws IOException thrown if error performing the markup
	 * @throws CancelledException if cancelled
	 */
	void markupField(FieldContext<T> fieldContext, MarkupSession markupSession)
			throws IOException, CancelledException;
}
