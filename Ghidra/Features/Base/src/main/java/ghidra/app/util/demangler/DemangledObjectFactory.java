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
package ghidra.app.util.demangler;

import util.demangler.*;

public class DemangledObjectFactory {

	private DemangledObjectFactory() {
		// factory
	}

	public static DemangledObject convert(GenericDemangledObject generic) throws DemangledException {
		if (generic instanceof GenericDemangledVariable) {
			return new DemangledVariable((GenericDemangledVariable) generic);
		}
		else if (generic instanceof GenericDemangledString) {
			return new DemangledString((GenericDemangledString) generic);
		}
		else if (generic instanceof GenericDemangledMethod) {
			return new DemangledMethod((GenericDemangledMethod) generic);
		}
		else if (generic instanceof GenericDemangledFunction) {
			return new DemangledFunction((GenericDemangledFunction) generic);
		}
		else if (generic instanceof GenericDemangledAddressTable) {
			return new DemangledAddressTable((GenericDemangledAddressTable) generic);
		}

		throw new DemangledException("Unknown GenericDemangledObject: " + generic.getClass());
	}

	public static DemangledType convert(GenericDemangledType generic) {
		if (generic instanceof GenericDemangledFunctionPointer) {
			return new DemangledFunctionPointer((GenericDemangledFunctionPointer) generic);
		}
		else if (generic instanceof GenericDemangledDataType) {
			return new DemangledDataType((GenericDemangledDataType) generic);
		}

		return new DemangledType(generic);
	}
}
