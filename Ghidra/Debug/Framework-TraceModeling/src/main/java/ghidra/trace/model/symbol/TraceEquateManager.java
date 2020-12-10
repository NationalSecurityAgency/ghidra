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
package ghidra.trace.model.symbol;

import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.exception.DuplicateNameException;

/**
 * TODO: Document me
 */
public interface TraceEquateManager extends TraceEquateOperations {
	static void validateName(String name) throws IllegalArgumentException {
		if (name == null) {
			throw new IllegalArgumentException("name cannot be null");
		}
		if (name.length() == 0) {
			throw new IllegalArgumentException("name cannot be empty string");
		}
		Pattern whitespace = Pattern.compile("\\s+");
		Matcher matcher = whitespace.matcher(name);
		if (matcher.find()) {
			throw new IllegalArgumentException("name cannot contain whitespace");
		}
	}

	TraceEquateSpace getEquateSpace(AddressSpace space, boolean createIfAbsent);

	TraceEquateRegisterSpace getEquateRegisterSpace(TraceThread thread, boolean createIfAbsent);

	TraceEquateRegisterSpace getEquateRegisterSpace(TraceStackFrame frame, boolean createIfAbsent);

	TraceEquate create(String name, long value)
			throws DuplicateNameException, IllegalArgumentException;

	TraceEquate getByName(String name);

	TraceEquate getByKey(long key);

	Collection<? extends TraceEquate> getByValue(long value);

	Collection<? extends TraceEquate> getAll();
}
