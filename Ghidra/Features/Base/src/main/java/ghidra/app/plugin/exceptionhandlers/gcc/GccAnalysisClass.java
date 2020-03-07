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
package ghidra.app.plugin.exceptionhandlers.gcc;

import ghidra.app.cmd.comments.SetCommentCmd;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;

/**
 * An abstract class that can be extended by other classes that perform part of the gcc analysis.
 * It provides some basic data types and methods for use by the extending class.
 */
public abstract class GccAnalysisClass {

	/* Class Constants */
	public static final String NEWLINE = System.getProperty("line.separator");

	/* Class Members */
	protected TaskMonitor monitor;
	protected Program program;
	protected int ptrSize;						// Default Pointer Size
	protected Pointer ptrDT;					// Pointer DataType of Default Pointer Size
	protected DWordDataType dwordDT;			// Double Word DataType

	/**
	 * Creates an abstract GccAnalysisClass object. Subclasses should call this constructor
	 * to initialize the program and task monitor.
	 * 
	 * @param monitor task monitor to see if the user has cancelled analysis.
	 * @param program the program being analyzed.
	 */
	public GccAnalysisClass(TaskMonitor monitor, Program program) {
		this.monitor = monitor;
		this.program = program;
	}

	/**
	 * Method that initializes the various pieces
	 * of information that are used throughout the
	 * program.
	 * 
	 * @param program the program being analyzed
	 */
	protected void init(Program program) {
		initPointerInfo();
		dwordDT = new DWordDataType();
	}

	/**
	 * Method that initializes information about the
	 * program's pointer size and creates an appropriate
	 * pointer data type (i.e. ptrDT)
	 */
	private void initPointerInfo() {
		ptrDT = PointerDataType.getPointer(null, -1);
	}

	/**
	 * Creates the specified DataType at the supplied address.
	 * 
	 * @param program the program being analyzed
	 * @param addr the address where data is created
	 * @param dt the type for the data
	 */
	protected static void createData(Program program, Address addr, DataType dt) {
		try {
			// try creating without clearing, the code units should be clear
			program.getListing().createData(addr, dt);
		}
		catch (CodeUnitInsertionException | DataTypeConflictException e) {
			CreateDataCmd dataCmd = new CreateDataCmd(addr, dt);
			dataCmd.applyTo(program);
		}
	}

	/**
	 * Creates the specified DataType at the supplied address. In
	 * addition, a comment of the specified type is also created at the address.
	 * 
	 * @param program the program being analyzed
	 * @param addr the address where data is created
	 * @param dt the type for the data
	 * @param comment the comment about the data
	 * @param commentType the type of comment ({@link CodeUnit#PLATE_COMMENT}, 
	 * {@link CodeUnit#PRE_COMMENT}, {@link CodeUnit#EOL_COMMENT}, {@link CodeUnit#POST_COMMENT},
	 * {@link CodeUnit#REPEATABLE_COMMENT}) 
	 */
	protected static void createAndCommentData(Program program, Address addr, DataType dt,
			String comment, int commentType) {
		createData(program, addr, dt);
		SetCommentCmd.createComment(program, addr, comment, commentType);
	}

}
