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
package ghidra.file.formats.android.dex.format;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.dwarf4.LEB128;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public class DebugInfoItem implements StructConverter {

	private int lineStart;
	private int lineStartLength;// in bytes
	private int parametersSize;
	private int parametersSizeLength;// in bytes
	private int [] parameterNames;
	private int [] parameterNamesLengths;
	private byte [] stateMachineOpcodes;

	public DebugInfoItem( BinaryReader reader ) throws IOException {
		LEB128 leb128 = LEB128.readUnsignedValue(reader);
		lineStart = leb128.asUInt32();
		lineStartLength = leb128.getLength();

		leb128 = LEB128.readUnsignedValue(reader);
		parametersSize = leb128.asUInt32();
		parametersSizeLength = leb128.getLength();

		parameterNames = new int[ parametersSize ];
		parameterNamesLengths = new int[ parametersSize ];

		for ( int i = 0 ; i < parametersSize ; ++i ) {
			leb128 = LEB128.readUnsignedValue(reader);

			parameterNames[i] = leb128.asUInt32() - 1;// uleb128p1
			parameterNamesLengths[i] = leb128.getLength();
		}

		int count = DebugInfoStateMachineReader.computeLength( reader.clone() );
		stateMachineOpcodes = reader.readNextByteArray( count );
	}

	/**
	 * <pre>
	 * The initial value for the state machine's line register. 
	 * Does not represent an actual positions entry.
	 * </pre>
	 */
	public int getLineStart( ) {
		return lineStart;
	}

	/**
	 * <pre>
	 * The number of parameter names that are encoded. 
	 * There should be one per method parameter, excluding an instance method's this, if any.
	 * </pre>
	 */
	public int getParametersSize( ) {
		return parametersSize;
	}

	/**
	 * <pre>
	 * String index of the method parameter name. 
	 * An encoded value of NO_INDEX indicates that no name is available for the associated parameter. 
	 * The type descriptor and signature are implied from the method descriptor and signature.
	 * </pre>
	 */
	public int [] getParameterNames( ) {
		return parameterNames;
	}

	public byte [] getStateMachineOpcodes( ) {
		return stateMachineOpcodes;
	}

	@Override
	public DataType toDataType( ) throws DuplicateNameException, IOException {
		StringBuilder builder = new StringBuilder( );
		builder.append( "debug_info_item" + "_" );
		builder.append( lineStartLength + "" );
		builder.append( parametersSizeLength + "" );
		builder.append( parametersSize + "" );
		builder.append( stateMachineOpcodes.length + "" );

		Structure structure = new StructureDataType( builder.toString( ), 0 );

		structure.add( new ArrayDataType( BYTE, lineStartLength, BYTE.getLength( ) ), "line_start", null );
		structure.add( new ArrayDataType( BYTE, parametersSizeLength, BYTE.getLength( ) ), "parameters_size", null );

		for ( int i = 0 ; i < parametersSize ; ++i ) {
			ArrayDataType dataType = new ArrayDataType( BYTE, parameterNamesLengths[ i ], BYTE.getLength( ) );
			structure.add( dataType, "parameter_" + i, null );
			builder.append( dataType.getLength( ) + "" );
		}

		ArrayDataType stateMachineArray = new ArrayDataType( BYTE, stateMachineOpcodes.length, BYTE.getLength( ) );
		structure.add( stateMachineArray, "state_machine", null );

		structure.setCategoryPath( new CategoryPath( "/dex/debug_info_item" ) );
		try {
			structure.setName( builder.toString( ) );
		}
		catch ( Exception e ) {
			// ignore
		}
		return structure;
	}
}
