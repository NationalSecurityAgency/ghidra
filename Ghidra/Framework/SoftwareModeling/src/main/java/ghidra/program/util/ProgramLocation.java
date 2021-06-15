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
package ghidra.program.util;

import java.lang.reflect.InvocationTargetException;
import java.util.Objects;

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.Msg;

/**
 * <CODE>ProgramLocation</CODE> provides information about a location in a program in the most
 * generic way.
 *
 * <p>
 * ProgramLocations refer to a specific location in a program and can be specified down to an
 * address, a field at that address, and within that field, a row, col, and character offset. The
 * field is not recorded directly, but by the subclass of the ProgramLocation. The "cursor position"
 * within a field is specified by three variables: row, col, and character offset. The row is
 * literally the row (line #) the cursor is on within the field, the column represents the display
 * item on that row (For example, in the bytes field the column will represent which "byte" the
 * cursor is on. Most fields only have one column item per row.) And finally, the character offset
 * is the character position within the display item specified by the row and column. Simple fields
 * like the address field and Mnemonic field will always have a row and column of 0.
 */
public class ProgramLocation implements Comparable<ProgramLocation> {

	protected Program program;
	protected Address addr;
	protected Address refAddr;
	private int[] componentPath;
	private Address byteAddr;
	private int row;
	private int col;
	private int charOffset;

	/**
	 * Construct a new ProgramLocation.
	 *
	 * @param program the program of the location
	 * @param addr address of the location; cannot be null; This could be a code unit minimum
	 *            address where the byteAddr is within the code unit.
	 * @param byteAddr address of the location; cannot be null
	 * @param componentPath array of indexes for each nested data component; the data index is the
	 *            data component's index within its parent; may be null
	 * @param refAddr the "referred to" address if the location is over a reference; may be null
	 * @param row the row within the field.
	 * @param col the display item index on the given row. (Note most fields only have one display
	 *            item per row)
	 * @param charOffset the character offset within the display item.
	 * @throws NullPointerException if {@code addr} or {@code program} is null
	 */
	public ProgramLocation(Program program, Address addr, Address byteAddr, int[] componentPath,
			Address refAddr, int row, int col, int charOffset) {

		if (program == null) {
			NullPointerException exc =
				new NullPointerException("Null program passed to ProgramLocation");
			showException(exc);
		}

		if (addr == null) {
			NullPointerException exc =
				new NullPointerException("Null address passed to ProgramLocation");
			showException(exc);
		}

		this.program = program;
		this.addr = addr;
		this.byteAddr = byteAddr;
		this.refAddr = refAddr;
		this.row = row;
		this.col = col;
		this.charOffset = charOffset;

		this.componentPath = componentPath;
	}

	/**
	 * Construct a new ProgramLocation for the given address. The address will be adjusted to the
	 * beginning of the {@link CodeUnit code unit} containing that address (if it exists). The
	 * original address can be retrieved using the {@link #getByteAddress()}" method.
	 * 
	 * @param program the program associated with this program location (also used to obtain a
	 *            code-unit-aligned address)
	 * @param addr address of the location; cannot be null
	 * @param componentPath array of indexes for each nested data component; the index is the data
	 *            component's index within its parent; may be null
	 * @param refAddr the "referred to" address if the location is over a reference; may be null
	 * @param row the row within the field.
	 * @param col the display item index on the given row. (Note most fields only have one display
	 *            item per row)
	 * @param charOffset the character offset within the display item.
	 * @throws NullPointerException if {@code addr} or {@code program} is null
	 */
	public ProgramLocation(Program program, Address addr, int[] componentPath, Address refAddr,
			int row, int col, int charOffset) {
		this(program, getCodeUnitAddress(program, addr), addr, componentPath, refAddr, row, col,
			charOffset);
	}

	/**
	 * Construct a new ProgramLocation for the given address. The address will be adjusted to the
	 * beginning of the {@link CodeUnit code unit} containing that address (if it exists). The
	 * original address can be retrieved using the {@link #getByteAddress()} method.
	 * 
	 * @param program the program associated with this program location (also used to obtain a
	 *            code-unit-aligned address)
	 * @param addr address for the location
	 * @throws NullPointerException if {@code addr} or {@code program} is null
	 */
	public ProgramLocation(Program program, Address addr) {
		this(program, getCodeUnitAddress(program, addr), addr, null, null, 0, 0, 0);
	}

	/**
	 * Construct a new ProgramLocation for the given address. The address will be adjusted to the
	 * beginning of the {@link CodeUnit code unit} containing that address (if it exists). The
	 * original address can be retrieved using the {@link #getByteAddress()} method.
	 * 
	 * @param program the program associated with this program location (also used to obtain a
	 *            code-unit-aligned address)
	 * @param addr address for the location
	 * @param row the row within the field.
	 * @param col the display item index on the given row. (Note most fields only have one display
	 *            item per row)
	 * @param charOffset the character offset within the display item.
	 * @throws NullPointerException if {@code addr} or {@code program} is null
	 */
	public ProgramLocation(Program program, Address addr, int row, int col, int charOffset) {
		this(program, getCodeUnitAddress(program, addr), addr, null, null, row, col, charOffset);
	}

	/**
	 * Construct a new ProgramLocation for the given address. The address will be adjusted to the
	 * beginning of the {@link CodeUnit code unit} containing that address (if it exists). The
	 * original address can be retrieved using the {@link #getByteAddress()} method.
	 * 
	 * @param program the program associated with this program location (also used to obtain a
	 *            code-unit-aligned address)
	 * @param addr address for the location
	 * @param refAddr the "referred to" address if the location is over a reference
	 * @throws NullPointerException if {@code addr} or {@code program} is null
	 */
	public ProgramLocation(Program program, Address addr, Address refAddr) {
		this(program, getCodeUnitAddress(program, addr), addr, null, refAddr, 0, 0, 0);
	}

	/**
	 * Default constructor required for restoring a program location from XML.
	 */
	public ProgramLocation() {
	}

	/**
	 * Returns the componentPath for the {@link CodeUnit code unit}. Null will be returned if the
	 * object is an {@link Instruction} or a top-level {@link Data} object.
	 */
	public int[] getComponentPath() {
		return componentPath;
	}

	/**
	 * Returns the program associated with this location.
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Returns the address associated with this location.
	 * 
	 * <p>
	 * Note: this may not be the same as the byte address. For example, in a {@link CodeUnit code
	 * unit} location this may be the minimum address of the code unit that contains the byte
	 * address.
	 */
	public Address getAddress() {
		return addr;
	}

	/**
	 * Returns the byte level address associated with this location.
	 */
	public Address getByteAddress() {
		return byteAddr;
	}

	/**
	 * Returns the "referred to" address if the location is over an address in some field.
	 */
	public Address getRefAddress() {
		return refAddr;
	}

	/**
	 * Save this program location to the given save state object.
	 * 
	 * @param obj the save state object for saving the location
	 */
	public void saveState(SaveState obj) {
		obj.putString("_CLASSNAME", getClass().getName());

		obj.putString("_ADDRESS", addr.toString());
		obj.putString("_BYTE_ADDR", byteAddr.toString());
		if (refAddr != null) {
			obj.putString("_REF_ADDRESS", refAddr.toString());
		}
		if (componentPath != null) {
			obj.putInts("_COMP_PATH", componentPath);
		}
		obj.putInt("_COLUMN", col);
		obj.putInt("_ROW", row);
		obj.putInt("_CHAR_OFFSET", charOffset);
	}

	/**
	 * Restore this program location using the given program and save state object.
	 * 
	 * @param program1 program to restore from
	 * @param obj the save state to restore from
	 */
	public void restoreState(Program program1, SaveState obj) {
		this.program = program1;
		String addrStr = obj.getString("_ADDRESS", "0");
		String byteAddrStr = obj.getString("_BYTE_ADDR", addrStr);
		String refAddrStr = obj.getString("_REF_ADDRESS", null);
		componentPath = obj.getInts("_COMP_PATH", null);
		addr = ProgramUtilities.parseAddress(program1, addrStr);
		byteAddr = ProgramUtilities.parseAddress(program1, byteAddrStr);
		if (refAddrStr != null) {
			refAddr = ProgramUtilities.parseAddress(program1, refAddrStr);
		}
		col = obj.getInt("_COLUMN", 0);
		row = obj.getInt("_ROW", 0);
		charOffset = obj.getInt("_CHAR_OFFSET", 0);

	}

	/**
	 * Get the program location for the given program and save state object.
	 * 
	 * @param program the program for the location
	 * @param saveState the state to restore
	 * @return the restored program location
	 */
	public static ProgramLocation getLocation(Program program, SaveState saveState) {
		String className = saveState.getString("_CLASSNAME", null);
		if (className == null) {
			return null;
		}

		try {
			Class<?> locClass = Class.forName(className);
			ProgramLocation loc = (ProgramLocation) locClass.getConstructor().newInstance();
			loc.restoreState(program, saveState);
			if (loc.getAddress() != null) {
				return loc;
			}
			// no address, it must be in a removed block; we can't use it
		}
		catch (RuntimeException e) { // restoreState may not parse the address if it is no longer valid.
		}
		catch (ClassNotFoundException e) {
			// not sure why we are ignoring this--if you know, then please let everyone else know
		}
		catch (InstantiationException | IllegalAccessException | NoSuchMethodException e) {
			Msg.showError(ProgramLocation.class, null, "Programming Error",
				"Class " + className + " must have public default constructor!", e);
		}
		catch (InvocationTargetException e) {
			Msg.showError(ProgramLocation.class, null, "Programming Error",
				"Class " + className + " default constructor threw an exception!", e);
		}
		return null;
	}

	@Override
	public int hashCode() {
		return Objects.hash(program, addr);
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append(getClass().getSimpleName());
		buf.append('@');
		buf.append(addr.toString());
		if (!addr.equals(byteAddr)) {
			buf.append(", byteAddr=");
			buf.append(byteAddr.toString());
		}
		if (refAddr != null) {
			buf.append(", refAddr=");
			buf.append(refAddr.toString());
		}
		if (componentPath != null && componentPath.length != 0) {
			buf.append(", componentPath=");
			for (int i = 0; i < componentPath.length; i++) {
				if (i != 0) {
					buf.append(':');
				}
				buf.append(Integer.toString(componentPath[i]));
			}
		}
		buf.append(", row=");
		buf.append(row);
		buf.append(", col=");
		buf.append(col);
		buf.append(", charOffset=");
		buf.append(charOffset);
		return buf.toString();
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (this == obj) {
			return true;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ProgramLocation other = (ProgramLocation) obj;
		if (program != other.program) {
			return false;
		}
		if (compareAddr(addr, other.addr) != 0) {
			return false;
		}
		if (compareAddr(refAddr, other.refAddr) != 0) {
			return false;
		}
		if (compareAddr(byteAddr, other.byteAddr) != 0) {
			return false;
		}
		if (!checkComponentPath(componentPath, other.componentPath)) {
			return false;
		}
		return row == other.row && col == other.col && charOffset == other.charOffset;
	}

	@Override
	public int compareTo(ProgramLocation other) {
		if (other == this) {
			return 0;
		}
		int result = ProgramLocationComparator.INSTANCE.compare(this, other);
		if (result == 0) {
			result = row - other.row;
			if (result == 0) {
				result = col - other.col;
				if (result == 0) {
					result = charOffset - other.charOffset;
				}
			}
		}
		return result;
	}

	private boolean checkComponentPath(int[] p1, int[] p2) {
		if (p1 == null) {
			return (p2 == null) || (p2.length == 0);
		}
		if (p2 == null) {
			return p1.length == 0;
		}
		// ok, neither are null
		if (p1.length != p2.length) {
			return false;
		}
		for (int i = 0; i < p1.length; i++) {
			if (p1[i] != p2[i]) {
				return false;
			}
		}
		return true;
	}

	protected static int compareAddr(Address addr1, Address addr2) {
		if (addr1 == null) {
			if (addr2 == null) {
				return 0;
			}
			return -1;
		}
		else if (addr2 == null) {
			return 1;
		}
		return addr1.compareTo(addr2);
	}

	private static Address getCodeUnitAddress(Program p, Address addr) {
		if (addr == null) {
			NullPointerException exc =
				new NullPointerException("Null address passed to ProgramLocation");
			showException(exc);
		}

		if (p == null) {
			return addr;
		}
		CodeUnit cu = p.getListing().getCodeUnitContaining(addr);

		// if the codeunit is a data, try and dig down to the lowest subdata containing the address
		if (cu instanceof Data) {
			Data data = (Data) cu;
			cu = data.getPrimitiveAt((int) addr.subtract(data.getAddress()));
		}

		if (cu != null) {
			return cu.getMinAddress();
		}
		return addr;
	}

	private static void showException(Exception exception) {
		Msg.showError(ProgramLocation.class, null, exception.getMessage(),
			exception.getMessage() + ".  Trace and remove this problem", exception);
	}

	/**
	 * Returns true if this location represents a valid location in the given program
	 * 
	 * @param testProgram the program to test if this location is valid.
	 * @return true if this location represents a valid location in the given program
	 */
	public boolean isValid(Program testProgram) {
		return addr == null || testProgram.getAddressFactory().isValidAddress(addr);
	}

	/**
	 * Returns the row within the program location.
	 * 
	 * @return the row within the program location.
	 */
	public int getRow() {
		return row;
	}

	/**
	 * Returns the character offset in the display item at the (row,col)
	 * 
	 * @return the character offset in the display item at the (row,col)
	 */
	public int getCharOffset() {
		return charOffset;
	}

	/**
	 * Returns the column index of the display piece represented by this location. For most
	 * locations, there is only one display item per row, in which case this value will be 0.
	 */
	public int getColumn() {
		return col;
	}

}
