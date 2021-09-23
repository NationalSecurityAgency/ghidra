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
package ghidra.file.formats.android.art;

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;

public final class ArtUtilities {

	static void createFragment(Program program, String fragmentName, Address start,
			Address end) throws Exception {
		ProgramModule module = program.getListing().getRootModule(0);
		ProgramFragment fragment = getFragment(module, fragmentName);
		if (fragment == null) {
			fragment = module.createFragment(fragmentName);
		}
		fragment.move(start, end.subtract(1));
	}

	static ProgramFragment getFragment(ProgramModule module, String fragmentName) {
		Group[] groups = module.getChildren();
		for (Group group : groups) {
			if (group.getName().equals(fragmentName)) {
				return (ProgramFragment) group;
			}
		}
		return null;
	}

	public static Address adjustForThumbAsNeeded(ArtHeader artHeader, Program program,
			Address address) {
		long displacement = address.getOffset();
		if (program.getLanguage()
				.getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("ARM"))) {
			if ((displacement & 0x1) == 0x1) {//thumb code?
				address = address.subtract(1);

				Register register = program.getLanguage().getRegister("TMode");
				RegisterValue value = new RegisterValue(register, BigInteger.valueOf(1));
				try {
					program.getProgramContext().setRegisterValue(address, address, value);
				}
				catch (ContextChangeException e) {
					//log.appendException( e );
					//ignore...
				}
			}
		}
		return address;
	}
}
