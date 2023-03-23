/* ###
 * IP: LICENSE
 */
package ghidra.machinelearning.functionfinding;

import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.table.ProgramLocationTableRowMapper;

public class FunctionStartRowObjectToAddressTableRowMapper
		extends ProgramLocationTableRowMapper<FunctionStartRowObject, Address> {

	@Override
	public Address map(FunctionStartRowObject rowObject, Program data,
			ServiceProvider serviceProvider) {
		return rowObject.getAddress();
	}

}
