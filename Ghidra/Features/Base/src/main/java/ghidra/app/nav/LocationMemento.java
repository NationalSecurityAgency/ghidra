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
package ghidra.app.nav;

import ghidra.framework.options.SaveState;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class LocationMemento {
	private static final String PROGRAM_PATH = "PROGRAM_PATH_";
	private static final String PROGRAM_ID = "PROGRAM_ID";
	private static final String MEMENTO_CLASS = "MEMENTO_CLASS";

	protected final ProgramLocation programLocation;
	private final Program program;

	public LocationMemento(Program program, ProgramLocation location) {
		this.program = program;
		this.programLocation = location;
	}

	public LocationMemento(SaveState saveState, Program[] programs) {
		String programPath = saveState.getString(PROGRAM_PATH, null);
		long programID = saveState.getLong(PROGRAM_ID, -1);
		program = getProgram(programs, programPath, programID);
		if (program == null) {
			throw new IllegalArgumentException("Unable to find program: " + programPath);
		}

		programLocation = ProgramLocation.getLocation(program, saveState);
		if (programLocation == null) {
			throw new IllegalArgumentException("Unable to create a program location!");
		}
	}

	public boolean isValid() {
		return program != null && programLocation != null;
	}

	private Program getProgram(Program[] programs, String pathName, long programID) {
		for (Program potentialProgram : programs) {
			if (potentialProgram.getUniqueProgramID() == programID) {
				return potentialProgram;
			}
		}
		return null;
	}

	public String getLocationDescription() {
		return programLocation.getAddress().toString();
	}

	public Program getProgram() {
		return program;
	}

	public ProgramLocation getProgramLocation() {
		return programLocation;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof LocationMemento)) {
			return false;
		}
		LocationMemento other = (LocationMemento) obj;
		return (program == other.program && compareLocations(programLocation, other.programLocation));
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + program.hashCode();

		Class<? extends ProgramLocation> clazz = programLocation.getClass();
		boolean isGeneric =
			(programLocation instanceof AddressFieldLocation) || clazz == ProgramLocation.class;
		if (!isGeneric) {
			// Only the generic location types can compare as equal when the addresses are the
			// same (see the equals() method).  If you change equals, change this method.
			result = prime * result + programLocation.getClass().hashCode();
		}

		result = prime * result + programLocation.getAddress().hashCode();
		return result;
	}

	@Override
	public String toString() {
		return "LocationMemento[location=" + programLocation + "]";
	}

	private boolean compareLocations(ProgramLocation loc1, ProgramLocation loc2) {
		if (loc1 == null || loc2 == null) {
			return false;
		}
		if (loc1.equals(loc2)) {
			return true;
		}
		if (!SystemUtilities.isEqual(loc1.getAddress(), loc2.getAddress())) {
			return false;
		}
		if (loc1.getClass() == loc2.getClass()) {
			return true;
		}
		// at this point we know they have the some addresses, but different location types (fields)
		// also consider generic program locations to be equal to addressField locations
		boolean isAddr1 =
			loc1 instanceof AddressFieldLocation || loc1.getClass() == ProgramLocation.class;
		boolean isAddr2 =
			loc2 instanceof AddressFieldLocation || loc2.getClass() == ProgramLocation.class;
		return isAddr1 & isAddr2;
	}

	public void saveState(SaveState saveState) {
		saveState.putString(MEMENTO_CLASS, getClass().getName());
		saveState.putString(PROGRAM_PATH, program.getDomainFile().toString());
		saveState.putLong(PROGRAM_ID, program.getUniqueProgramID());
		programLocation.saveState(saveState);
	}

	@SuppressWarnings("unchecked")
	// we saved the class, it should be the right type
	public static LocationMemento getLocationMemento(SaveState saveState, Program[] programs) {
		String className = saveState.getString(MEMENTO_CLASS, null);
		if (className == null) {
			return null;
		}

		try {
			Class<? extends LocationMemento> mementoClass =
				(Class<? extends LocationMemento>) Class.forName(className);

			Constructor<? extends LocationMemento> constructor =
				mementoClass.getConstructor(SaveState.class, Program[].class);
			return constructor.newInstance(saveState, programs);
		}
		catch (ClassNotFoundException e) {
			// class must have been deleted or renamed
		}
		catch (InstantiationException e) {
			Msg.showError(ProgramLocation.class, null, "Programming Error", "Class " + className +
				" must have public constructor!", e);
		}
		catch (IllegalAccessException e) {
			Msg.showError(ProgramLocation.class, null, "Programming Error", "Class " + className +
				" must have public constructor!", e);
		}
		catch (NoSuchMethodException e) {
			Msg.showError(ProgramLocation.class, null, "Programming Error", "Class " + className +
				" must have a public constructor that takes a SaveState " + "and a Program[]!", e);
			e.printStackTrace();
		}
		catch (InvocationTargetException e) {
			Throwable cause = e.getCause();
			if (cause instanceof IllegalArgumentException) {
				throw (IllegalArgumentException) cause;
			}

			// Cause could be null here, so protect.
			String message = cause == null ? "" : cause.getMessage();
			throw new IllegalArgumentException("Unexpected exception restoring memento: " + message);
		}
		return null;

	}

}
