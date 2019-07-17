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
package ghidra.util.table.field;

import ghidra.app.plugin.core.analysis.ReferenceAddressPair;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

/**
 * This table field displays the name of the function containing the from address for the reference.
 */
public class ReferenceFromFunctionTableColumn 
        extends ProgramLocationTableColumnExtensionPoint<ReferenceAddressPair,  String > {
	
	@Override
    public String getColumnDisplayName(Settings settings) {
        return getColumnName();
    }
	
	@Override
    public String getColumnName() {
		return "From Function";
	}
	
	@Override
    public String getValue(ReferenceAddressPair rowObject, Settings settings, Program pgm, 
	    ServiceProvider serviceProvider) 
	throws IllegalArgumentException {
		Function fromFunction = getFunction(rowObject, pgm);
		return (fromFunction != null) ? fromFunction.toString() : null;
	}
	
	public ProgramLocation getProgramLocation(ReferenceAddressPair rowObject, Settings settings,
	        Program program, ServiceProvider serviceProvider) {
		Address address = getFromAddress(rowObject);
		return new ProgramLocation(program, address);
	}
	
	private Address getFromAddress(ReferenceAddressPair rowObject) throws IllegalArgumentException {
	    return rowObject.getSource();
	}
	
	private Function getFunction(ReferenceAddressPair rowObject, Program pgm) 
	        throws IllegalArgumentException {
		Address fromAddress = getFromAddress(rowObject);
		if (fromAddress != null) {
			return pgm.getFunctionManager().getFunctionContaining(fromAddress);
		}
		return null;
	}
}
