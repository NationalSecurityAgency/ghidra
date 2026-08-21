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
package ghidra.lisa.pcode.analyses;

import ghidra.lisa.pcode.locations.InstLocation;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import it.unive.lisa.analysis.SemanticException;
import it.unive.lisa.analysis.SemanticOracle;
import it.unive.lisa.analysis.nonrelational.value.BaseNonRelationalValueDomain;
import it.unive.lisa.program.cfg.ProgramPoint;
import it.unive.lisa.program.cfg.statement.Assignment;
import it.unive.lisa.symbolic.value.PushAny;

/**
 * @param <T> the concrete type of this domain
 */
public interface PcodeNonRelationalValueDomain<T extends PcodeNonRelationalValueDomain<T>>
		extends BaseNonRelationalValueDomain<T> {

	T getValue(RegisterValue rv);

	default T getValue(ProgramPoint pp) {
		InstLocation loc = (InstLocation) pp.getLocation();
		Function f = loc.function();
		if (f != null && pp instanceof Assignment a) {
			Program program = f.getProgram();
			try {
				Address address = program.getAddressFactory()
						.getRegisterSpace()
						.getAddress(a.getLeft().toString());
				Register r = program.getRegister(address);
				if (r != null) {
					RegisterValue rv =
						program.getProgramContext().getRegisterValue(r, f.getEntryPoint());
					return getValue(rv);
				}
			}
			catch (AddressFormatException e) {
				// IGNORE
			}
		}
		return getValue((RegisterValue) null);
	}

	@Override
	default T evalPushAny(
			PushAny pushAny,
			ProgramPoint pp,
			SemanticOracle oracle)
			throws SemanticException {
		T v = getValue(pp);
		return v == null ? top() : v;
	}
}
