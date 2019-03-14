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
package ghidra.program.model.data;

/**
 * Exception thrown when an attempt is made to add a data type to a category
 * and the category has a data type by that name but the types do not
 * match.
 */
public class DataTypeConflictException extends RuntimeException {
	DataType datatype1;
	DataType datatype2;

	/**
	 * Construct a new DataTypeConflictException with no message
	 */
	public DataTypeConflictException() {
		super();
	}

	/**
	 * Construct a new DataTypeConflictException with the given message
	 *
	 * @param msg    the exception message
	 */
	public DataTypeConflictException(String msg) {
		super(msg);
	}

	/**
	 * Construct a new DataTypeConflictException with the given datatypes.
	 * The message will indicate there is a conflict between the two data types.
	 *
	 * @param dt1    the first of the two conflicting data types. 
	 * (The new data type.)
	 * @param dt2    the second of the two conflicting data types. 
	 * (The existing data type.)
	 */
	public DataTypeConflictException(DataType dt1, DataType dt2) {
		super("Data type \"" + dt1.getPathName() + "\" conflicts\nwith data type \"" +
			dt2.getPathName() + "\".\n");
		this.datatype1 = dt1;
		this.datatype2 = dt2;
	}

	/**
	 * Returns the conflicting data types in a Data Type array of size 2. 
	 * The first entry is the first data type in conflict. 
	 * The second entry is the second data type in conflict. 
	 * <P>Note: These values can be null. They are only known if this
	 * object was created using the constructor that has the conflicting
	 * data types as parameters.
	 * @return the two conflicting data types or nulls.
	 */
	public DataType[] getConflictingDataTypes() {
		return new DataType[] { this.datatype1, this.datatype2 };
	}
}
