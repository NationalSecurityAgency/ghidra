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
package ghidra.file.formats.bplist;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

import java.io.IOException;

public class NSNumber extends NSObject {

	private NSNumberTypes type;
	private double value;

	public NSNumber( boolean value ) {
		this.type = NSNumberTypes.BOOLEAN;
		this.value = value ? 1 : 0;
	}

	public NSNumber( byte value ) {
		this.type = NSNumberTypes.BYTE;
		this.value = value;
	}

	public NSNumber( short value ) {
		this.type = NSNumberTypes.SHORT;
		this.value = value;
	}

	public NSNumber( int value ) {
		this.type = NSNumberTypes.INTEGER;
		this.value = value;
	}

	public NSNumber( long value ) {
		this.type = NSNumberTypes.LONG;
		this.value = value;
	}

	public NSNumber( double value ) {
		this.type = NSNumberTypes.REAL;
		this.value = value;
	}

	@Override
	public String getType() {
		return "NSNumber";
	}

	public NSNumberTypes getNumberType() {
		return type;
	}

	public double doubleValue() {
		return value;
	}

	public float floatValue() {
		return (float ) value;
	}

	public int intValue() {
		return (int ) value;
	}

	public boolean booleanValue() {
		return value != 0;
	}

	public long longValue() {
		return (long ) value;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "NSNumber_" + type.name( ), 0 );
		structure.add( BYTE, "objectDescriptor", null );
		if ( type == NSNumberTypes.BYTE ) {
			structure.add( BYTE, "value", null );
		}
		else if ( type == NSNumberTypes.SHORT ) {
			structure.add( WORD, "value", null );
		}
		else if ( type == NSNumberTypes.INTEGER ) {
			structure.add( DWORD, "value", null );
		}
		else if ( type == NSNumberTypes.LONG ) {
			structure.add( QWORD, "value", null );
		}
		else if ( type == NSNumberTypes.REAL ) {
			structure.add( new DoubleDataType( ), "value", null );
		}
		else if ( type == NSNumberTypes.BOOLEAN ) {
			//don't add anything
		}
		return structure;
	}

	@Override
	public String toString() {
		switch ( type ) {
			case BOOLEAN: {
				return "" + booleanValue( );
			}
			case REAL: {
				return "" + doubleValue( );
			}
			case BYTE:
			case SHORT:
			case INTEGER:
			case LONG: {
				return "" + longValue( );
			}
		}
		throw new RuntimeException( );
	}
}
