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
package ghidra.app.cmd.data;

import ghidra.app.util.datatype.microsoft.DataApplyOptions;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * This is the abstract command to extend when creating a specific data type or related data type. 
 */
public abstract class AbstractCreateDataBackgroundCmd<T extends AbstractCreateDataTypeModel>
		extends BackgroundCommand {

	protected final String name;
	private Address address;
	protected final int count;
	protected final DataValidationOptions validationOptions;
	protected final DataApplyOptions applyOptions;
	protected T model;
	protected TaskMonitor monitor;

	/**
	 * Constructs an abstract command for applying a dataType, that extends this class,
	 * at the address indicated by the model.
	 * @param model the model for the data type
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	protected AbstractCreateDataBackgroundCmd(T model, DataApplyOptions applyOptions) {
		super("Create " + model.getName() + " Data", true, true, true);
		this.model = model;
		this.name = model.getName();
		this.address = model.getAddress();
		this.count = model.getCount();
		validationOptions = model.getValidationOptions();
		this.applyOptions = applyOptions;
	}

	/**
	 * Constructs a command for applying a specific dataType at an address using the default 
	 * data validation options and default data apply options.
	 * @param name the name indicating the data type being created.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create. If more than 1, then an array
	 * of the data type will be created where count indicates the number of elements.
	 * data too.
	 */
	protected AbstractCreateDataBackgroundCmd(String name, Address address, int count) {
		this(name, address, count, new DataValidationOptions(), new DataApplyOptions());
	}

	/**
	 * Constructs a command for applying a specific dataType at an address.
	 * @param name the name indicating the data type being created.
	 * @param address the address where the data should be created using the data type.
	 * @param count the number of the indicated data type to create. If more than 1, then an array
	 * of the data type will be created where count indicates the number of elements.
	 * @param validationOptions the options for controlling how validation is performed when 
	 * determining whether or not to create the data structure at the indicated address.
	 * @param applyOptions the options for creating the new data structure and its associated
	 * markup in the program as well as whether to follow other data references and create their 
	 * data too.
	 */
	protected AbstractCreateDataBackgroundCmd(String name, Address address, int count,
			DataValidationOptions validationOptions, DataApplyOptions applyOptions) {
		super("Create " + name + " Data", true, true, true);
		this.name = name;
		this.address = address;
		this.count = count;
		this.validationOptions = validationOptions;
		this.applyOptions = applyOptions;
	}

	@Override
	public final boolean applyTo(DomainObject obj, TaskMonitor taskMonitor) {
		try {
			if (!(obj instanceof Program)) {
				String message = "Can only apply a " + name + " data type to a program.";
				handleError(message);
				return false;
			}
			return doApplyTo((Program) obj, taskMonitor);
		}
		catch (CancelledException e) {
			setStatusMsg("User cancelled " + getName() + ".");
			// FUTURE: Throw this exception instead of catching it, once BackgroundCommand throws it.
			return false;
		}
	}

	/**
	 * Gets the model that is used to validate and create the data type for this command.
	 * @param program the program where this command is applying the data type.
	 * @return the data type's model.
	 */
	protected abstract T createModel(Program program);

	/**
	 * Gets the data type that needs to be validated and created by this command.
	 * @return the data type or null.
	 */
	protected final DataType getDataType() {
		// If model isn't initialized, then we shouldn't even be getting to this point.
		// The create...() methods use model prior to calling this method.
		return model.getDataType();
	}

	/**
	 * Creates the data type for this command and may also create referred to data types. 
	 * Also creates references, symbols, and functions as indicated by the options.
	 * @param program the program where this command will create the data type.
	 * @param taskMonitor a task monitor for cancelling or providing status information while 
	 * creating the data type.
	 * @return true if the data type creation completes successfully.
	 * @throws CancelledException if the user cancels this task.
	 */
	protected boolean doApplyTo(Program program, TaskMonitor taskMonitor)
			throws CancelledException {

		try {
			monitor = taskMonitor;
			monitor.checkCanceled();

			model = createModel(program);
			model.validate();

			// Are there any instructions in the way?
			try {
				if (model.isBlockedByInstructions()) {
					String message =
						"Cannot create data in " + program.getDomainFile().getPathname() +
							" using " + model.getName() + " from " + model.getAddress() + " to " +
							model.getEndAddress() + " since there are instructions in the way.";
					handleErrorMessage(program, model.getAddress(), message);
					return false;
				}
			}
			catch (InvalidDataTypeException e) {
				handleErrorMessage(program, model.getAddress(), e.getMessage());
				return false;
			}

			boolean dataWasCreated = createData();

			boolean success = true;

			// Create markup for the data just created.
			try {
				createMarkup();
			}
			catch (InvalidInputException e) {
				// Catch the exception and output the error, but still should create 
				// associated data if possible, even though markup failed.
				handleErrorMessage(program, name, address, address, e);
				success = false;
			}

			// If data type didn't exist (was created) and following data when applying,
			if (dataWasCreated && applyOptions.shouldFollowData()) {
				// create any data referred to by the data just created
				success = createAssociatedData();
			}
			setStatusMsg(getName() + " completed successfully!");
			return success;
		}
		catch (AddressOutOfBoundsException | CodeUnitInsertionException | DataTypeConflictException
				| InvalidDataTypeException e) {
			handleErrorMessage(program, name, address, address, e);
			return false;
		}
	}

	/**
	 * Creates data at this command's address using the data type obtained from the model.
	 * <br>If you need to create data other than by using the data type returned from getDataType(),
	 * you should override this method.
	 * @return false if the data type was not created because it already exists, true otherwise
	 * @throws CodeUnitInsertionException if the data can't be created.
	 * @throws CancelledException if the user cancels this task.
	 */
	protected boolean createData() throws CodeUnitInsertionException, CancelledException {

		Program program = model.getProgram();
		Memory memory = program.getMemory();
		DataType dt = getDataType();
		if (dt == null) {
			throw new CodeUnitInsertionException(
				"Unable to get data type from model, " + model.getName() + ".");
		}
		if (!memory.getLoadedAndInitializedAddressSet().contains(address)) {
			String message = "Can't create an " + dt.getName() + " @ " + address +
				" which isn't in loaded and initialized memory for " + program.getName();
			throw new CodeUnitInsertionException(message);
		}

		// When creating data, this will create an array with count number of elements
		// of the model's data type if the data type obtained from the model hasn't
		// already done so.
		if (!model.isDataTypeAlreadyBasedOnCount() && count > 1) {
			// If there are multiple then create as an array.
			dt = new ArrayDataType(dt, count, dt.getLength(), program.getDataTypeManager());
		}

		monitor.checkCanceled();

		// Is the data type already applied at the address?
		if (matchingDataExists(dt, program, address)) {
			return false;
		}

		monitor.checkCanceled();

		// Create data at the address using the datatype.
		DataUtilities.createData(program, address, dt, dt.getLength(), false, getClearDataMode());

		return true;
	}

	/**
	 * Check for data at the indicated address in the specified program and determine if it has
	 * the desired data type.
	 * @param dt the desired data type for the data
	 * @param program the program to be checked
	 * @param startAddress the address to check for the data
	 * @return true if data with the desired data type exists at the indicated address in the 
	 * specified program.
	 */
	protected boolean matchingDataExists(DataType dt, Program program, Address startAddress) {
		Listing listing = program.getListing();
		Data dataAt = listing.getDataAt(startAddress);
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		DataType resolvedDt = dataTypeManager.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
		if (dataAt != null && dataAt.getDataType() == resolvedDt) {
			return true; // Already set to the desired data type.
		}
		return false;
	}

	/**
	 * Creates references, symbols, and functions for this data type as indicated by the options.
	 * @return true if all desired types of associated annotations were created.
	 * @throws CancelledException is thrown if the user cancels this command.
	 * @throws InvalidInputException if the model doesn't have valid information for creating
	 * some of the markup.
	 * @throws InvalidDataTypeException if this model or an associated model, which is needed
	 * for some of the markup, isn't valid
	 */
	protected abstract boolean createMarkup()
			throws CancelledException, InvalidInputException, InvalidDataTypeException;

	/**
	 * Creates the associated data that is indicated by the model's data type components. 
	 * Also creates references, symbols, and functions as indicated by the options.
	 * @return true if all associated data was created that was desired.
	 * throws CancelledException is thrown if the user cancels this command.
	 */
	protected abstract boolean createAssociatedData() throws CancelledException;

	/**
	 * Creates an error message that the named type of data structure couldn't be created at the 
	 * indicated address and outputs the error message to the log and also as a status message for 
	 * this command. This also creates a bookmark with the error message at the indicated address.
	 * @param program the program where the error bookmark should be created.
	 * @param dataName the data type name of the data that couldn't be created.
	 * @param dataAddress the address where the data couldn't be created.
	 * @param bookmarkAddress the address where the error bookmark should be created.
	 */
	protected void handleErrorMessage(Program program, String dataName, Address dataAddress,
			Address bookmarkAddress) {
		handleErrorMessage(program, dataName, dataAddress, bookmarkAddress, null);
	}

	/**
	 * Creates an error message that the named type of data structure couldn't be created at the 
	 * indicated address and outputs the error message to the log and also as a status message for 
	 * this command. This also creates a bookmark with the error message at the indicated address.
	 * @param program the program where the error bookmark should be created.
	 * @param dataName the data type name of the data that couldn't be created.
	 * @param dataAddress the address where the data couldn't be created.
	 * @param bookmarkAddress the address where the error bookmark should be created.
	 * @param e1 the exception whose message should be added to the error in the log. It's message
	 * gives additional details about why the data creation failed.
	 */
	protected void handleErrorMessage(Program program, String dataName, Address dataAddress,
			Address bookmarkAddress, Exception e1) {
		String message = "Couldn't create " + dataName + " data @ " + dataAddress + ".";
		String detailedMessage =
			(e1 == null || e1.getMessage() == null) ? message : (message + " " + e1.getMessage());
		handleErrorMessage(program, bookmarkAddress, detailedMessage, message);
	}

	/**
	 * Output the error message to the log and as a status message for this command. This also
	 * creates a bookmark with the error message at the indicated address.
	 * @param program the program where the error bookmark should be created.
	 * @param bookmarkAddress the address where an error bookmark should be created.
	 * @param message the error message.
	 */
	protected void handleErrorMessage(Program program, Address bookmarkAddress, String message) {
		handleErrorMessage(program, bookmarkAddress, message, message);
	}

	/**
	 * Output the error message to the log and output a possibly shorter status message for this 
	 * command. This also creates a bookmark with the error message at the indicated address.
	 * @param program the program where the error bookmark should be created.
	 * @param bookmarkAddress the address where an error bookmark should be created.
	 * @param errorMessage the detailed error message.
	 * @param statusMessage an abbreviated error message that will appear as a status message.
	 */
	protected void handleErrorMessage(Program program, Address bookmarkAddress, String errorMessage,
			String statusMessage) {
		Msg.error(this, errorMessage);
		setStatusMsg(statusMessage);
		if (applyOptions.shouldCreateBookmarks()) {
			BookmarkManager bookmarkManager = program.getBookmarkManager();
			bookmarkManager.setBookmark(bookmarkAddress, BookmarkType.ERROR, "Data", errorMessage);
		}
	}

	/**
	 * Output the error message to the log and as a status message for this command.
	 * @param message the error message.
	 */
	protected void handleError(String message) {
		Msg.error(this, message);
		setStatusMsg(message);
	}

	protected ClearDataMode getClearDataMode() {
		return (applyOptions.shouldClearDefinedData()) ? ClearDataMode.CLEAR_ALL_CONFLICT_DATA
				: ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA;
	}

	/**
	 * Get the address for the data item to be processed by the base implementation.
	 * In general this is the initial model address set when the command was created.
	 * 
	 * @return the address of the data item being created.
	 */
	final protected Address getDataAddress() {
		return address;
	}

	/**
	 * Set the address of the data item to be applied.
	 * Can be used for sub classes that need to apply multiple data items.
	 * 
	 * @param addr set the current data address
	 */
	final protected void setDataAddress(Address addr) {
		address = addr;
	}
}
