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
package ghidra.app.plugin.core.decompile.actions;

import java.util.List;

import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import utility.function.Callback;

/**
 * Create an equate in the table for the specific Address and hash value.
 * The equate is not assumed to be attached to a particular instruction operand and
 * uses the dynamic hash value to identify the particular constant (within p-code) to label.
 * 
 * If altAddress is non-null and the other alt* fields are filled in, the task attempts
 * to set the equation on the altAddress first to get the representation of the p-code
 * constant at convertAddress to change.  After the decompilation finishes, the representation
 * is checked, and if it did not change, the alt* equate is removed and an equate is created
 * directly for the convertAddress;
 */
public class ConvertConstantTask implements Callback {
	private DecompilerActionContext context;
	private Program program;
	private Address convertAddress;		// The primary address of the Equate
	private String convertName;			// The primary name to use in the Equate table
	private Varnode convertVn;			// The Varnode holding the constant value being equated
	private long convertHash;			// A dynamic hash locating the constant Varnode in data-flow
	private int convertIndex;			// The scalar index associated with the primary Equate (or -1)
	private boolean convertSigned;

	private Address altAddress = null;	// Alternate location of constant
	private int altIndex;				// Index of alternate scalar
	private String altName = null;		// Alternate equate name
	private long altValue;				// Alternate value 

	public ConvertConstantTask(Varnode vn, boolean isSigned) {
		convertVn = vn;
		convertSigned = isSigned;
	}

	/**
	 * Construct a primary Equate task
	 * @param context is the action context for the task
	 * @param name is the primary Equate name
	 * @param addr is the primary address of the Equate
	 * @param vn is the constant Varnode being equated
	 * @param hash is the dynamic hash
	 * @param index is the operand index if the Equate is known to label an instruction operand
	 */
	public ConvertConstantTask(DecompilerActionContext context, String name, Address addr,
			Varnode vn, long hash, int index) {
		this.context = context;
		program = context.getProgram();
		convertName = name;
		convertAddress = addr;
		convertVn = vn;
		convertHash = hash;
		convertIndex = index;
	}

	/**
	 * Establish an alternate Equate to try before falling back on the primary Equate
	 * @param name is the alternate name of the Equate
	 * @param addr is the alternate address
	 * @param index is the operand index
	 * @param value is the alternate constant value to equate
	 */
	public void setAlternate(String name, Address addr, int index, long value) {
		altName = name;
		altAddress = addr;
		altValue = value;
		altIndex = index;
	}

	/**
	 * @return the primary value being equated
	 */
	public long getValue() {
		return convertVn.getOffset();
	}

	/**
	 * @return the size of constant (Varnode) being equated
	 */
	public int getSize() {
		return convertVn.getSize();
	}

	/**
	 * @return true if the constant value is treated as a signed integer
	 */
	public boolean isSigned() {
		return convertSigned;
	}

	/**
	 * Remove any preexisting equate reference with the same address and hash as the
	 * primate equate.
	 */
	private void removePrimaryReference() {
		EquateTable equateTable = program.getEquateTable();
		List<Equate> equates = equateTable.getEquates(convertAddress);
		for (Equate equate : equates) {
			List<EquateReference> references = equate.getReferences(convertAddress);
			for (EquateReference ref : references) {
				if (ref.getDynamicHashValue() == convertHash) {
					if (equate.getReferenceCount() <= 1) {
						equateTable.removeEquate(equate.getName());
					}
					else {
						equate.removeReference(convertHash, convertAddress);
					}
					return;
				}
			}
		}
	}

	/**
	 * Remove and preexisting equate reference with the same address and hash as the
	 * alternate equate.
	 */
	private void removeAlternateReference() {
		EquateTable equateTable = program.getEquateTable();
		List<Equate> equates = equateTable.getEquates(altAddress);
		for (Equate equate : equates) {
			List<EquateReference> references = equate.getReferences(altAddress);
			for (EquateReference ref : references) {
				if (ref.getOpIndex() == altIndex) {
					if (equate.getReferenceCount() <= 1) {
						equateTable.removeEquate(equate.getName());
					}
					else {
						equate.removeReference(altAddress, altIndex);
					}
					return;
				}
			}
		}
	}

	/**
	 * Add equate based on the alternate constant information: altAddress, altName, altIndex
	 * @throws DuplicateNameException if there is already an equate with same name but different value
	 * @throws InvalidInputException if the equate name is illegal
	 */
	private void addPrimaryEquate() throws DuplicateNameException, InvalidInputException {
		EquateTable equateTable = program.getEquateTable();
		Equate equate = equateTable.getEquate(convertName);

		if (equate != null && equate.getValue() != convertVn.getOffset()) {
			String msg = "Equate named " + convertName + " already exists with value of " +
				equate.getValue() + ".";
			throw new DuplicateNameException(msg);
		}

		if (equate == null) {
			equate = equateTable.createEquate(convertName, convertVn.getOffset());
		}

		// Add reference to existing equate
		if (convertHash != 0) {
			equate.addReference(convertHash, convertAddress);
		}
		else {
			equate.addReference(convertAddress, convertIndex);
		}
	}

	/**
	 * Add equate based on the direct constant information: convertAddress, convertName, convertHash
	 * @throws DuplicateNameException if there is already an equate with same name but different value
	 * @throws InvalidInputException if the equate name is illegal
	 */
	private void addAlternateEquate() throws InvalidInputException, DuplicateNameException {
		EquateTable equateTable = program.getEquateTable();
		Equate equate = equateTable.getEquate(altName);

		if (equate != null && equate.getValue() != altValue) {
			String msg = "Equate named " + altName + " already exists with value of " +
				equate.getValue() + ".";
			throw new DuplicateNameException(msg);
		}

		if (equate == null) {
			equate = equateTable.createEquate(altName, altValue);
		}

		equate.addReference(altAddress, altIndex);
	}

	/**
	 * Create a reference to primary equate, removing any previous reference.
	 * If an alternate equate is given, remove any existing reference to it as well.
	 */
	private void applyPrimaryEquate() {

		int transaction = program.startTransaction("Convert constant");
		boolean commit = false;
		try {
			if (altAddress != null) {
				removeAlternateReference();
			}
			removePrimaryReference();
			addPrimaryEquate();
			commit = true;
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Convert Failed", e.getMessage());
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Convert Failed", e.getMessage());
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	/**
	 * Create a reference to the alternate equate.
	 */
	private void applyAlternateEquate() {
		int transaction = program.startTransaction("Convert constant");
		boolean commit = false;
		try {
			addAlternateEquate();
			commit = true;
		}
		catch (DuplicateNameException e) {
			Msg.showError(this, null, "Convert Failed", e.getMessage());
		}
		catch (InvalidInputException e) {
			Msg.showError(this, null, "Convert Failed", e.getMessage());
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	/**
	 * Look for the EquateSymbol pointing to the altAddress, attached to the constant
	 * @return true if we find the EquateSymbol, false otherwise
	 */
	private boolean isAlternatePlaced() {
		HighFunction highFunction = context.getHighFunction();	// Get the updated HighFunction
		if (highFunction == null) {
			return false;
		}
		// Varnode itself should be unchanged
		Varnode vn = DynamicHash.findVarnode(highFunction, convertAddress, convertHash);
		if (vn == null) {
			return false;
		}
		HighSymbol symbol = vn.getHigh().getSymbol();	// But now it should have an equate on it
		if (!(symbol instanceof EquateSymbol)) {
			return false;
		}
		EquateSymbol eqSymbol = (EquateSymbol) symbol;
		if (!eqSymbol.getPCAddress().equals(altAddress)) {
			return false;
		}
		return true;
	}

	/**
	 * Callback executed after the alternative equate is placed and the DecompilerProvider has updated its window.
	 * We check to see if the equate reached the desired constant in the decompiler.
	 * If not, we remove the alternate equate and place a direct equate
	 */
	@Override
	public void call() {
		if (isAlternatePlaced()) {
			return;
		}
		applyPrimaryEquate();
	}

	/**
	 * Run the convert task.  If the task is given an alternate equate, this is placed, otherwise
	 * the primary equate is placed.  If an alternate is placed, a thread is scheduled to check if
	 * the alternate equate reached the constant Varnode.  If not the alternate equate reference is
	 * removed, and the task falls back and places the primary equate.
	 */
	public void runTask() {
		if (altAddress != null) {
			applyAlternateEquate();
			try {
				Thread.sleep(50);		// Let the decompiler get going
			}
			catch (InterruptedException e) {
				return;
			}
			context.getComponentProvider().doWheNotBusy(this);
		}
		else {
			applyPrimaryEquate();
		}
	}
}
