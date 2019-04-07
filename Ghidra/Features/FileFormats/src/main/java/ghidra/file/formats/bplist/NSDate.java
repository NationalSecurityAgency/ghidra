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
import java.util.Date;

public class NSDate extends NSObject {
	public final static long EPOCH = 978307200000L;//Sun Dec 31 19:00:00 EST 2000

	private double value;

	public NSDate( double value ) {
		this.value = value;
	}

	@Override
	public String getType() {
		return "NSDate";
	}

	public Date getDate() {
		return new Date( EPOCH + (long ) ( 1000 * value ) );
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		Structure structure = new StructureDataType( "NSDate", 0 );
		structure.add( BYTE, "objectDescriptor", null );
		structure.add( new DoubleDataType( ), "date", null );
		return structure;
	}

	@Override
	public String toString() {
		return getDate( ).toString( );
	}
}
