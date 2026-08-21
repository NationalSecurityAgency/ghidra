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
package ghidra.trace.model.target.info;

import java.util.List;
import java.util.function.Function;

import ghidra.trace.database.target.DBTraceObject;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.util.classfinder.ExtensionPoint;

public interface TraceObjectInterfaceFactory extends ExtensionPoint {

	record Constructor<I extends TraceObjectInterface>(Class<I> iface,
			Function<? super DBTraceObject, ? extends I> ctor) {}

	static <I extends TraceObjectInterface> Constructor<I> ctor(Class<I> iface,
			Function<? super DBTraceObject, ? extends I> ctor) {
		return new Constructor<>(iface, ctor);
	}

	List<Constructor<?>> getInterfaceConstructors();
}
