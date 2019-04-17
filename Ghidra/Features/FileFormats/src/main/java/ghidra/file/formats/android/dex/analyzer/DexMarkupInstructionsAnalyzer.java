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
package ghidra.file.formats.android.dex.analyzer;

import java.util.List;
import java.util.StringTokenizer;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.dex.format.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class DexMarkupInstructionsAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze( Program program, AddressSetView set, TaskMonitor monitor, MessageLog log ) throws Exception {
		monitor.setMaximum( set == null ? program.getMemory( ).getSize( ) : set.getNumAddresses( ) );
		monitor.setProgress( 0 );

		DexAnalysisState analysisState = DexAnalysisState.getState(program);
		DexHeader header = analysisState.getHeader();

		// Set-up reader for fill_array_data
		ByteProvider provider = new MemoryByteProvider( program.getMemory( ), program.getMinAddress( ) );
		BinaryReader reader = new BinaryReader( provider, true );

		Listing listing = program.getListing( );

		InstructionIterator instructionIterator = listing.getInstructions( set, true );
		while ( instructionIterator.hasNext( ) ) {
			Instruction instruction = instructionIterator.next( );

			monitor.checkCanceled( );
			monitor.incrementProgress( 1 );
			monitor.setMessage( "DEX: Instruction markup ... " + instruction.getMinAddress( ) );

			String mnemonicString = instruction.getMnemonicString( );

			if ( mnemonicString.startsWith( "invoke_super_quick" ) ) {
				//ignore...
			}
			else if ( mnemonicString.startsWith( "invoke_virtual_quick" ) ) {
				//ignore...
			}
			else if ( mnemonicString.startsWith( "invoke_object_init_range" ) ) {
				//ignore...
			}
			else if ( mnemonicString.indexOf( "quick" ) > 0 ) {
				//ignore...
			}
			else if ( mnemonicString.startsWith( "const_string" ) ) {
				Scalar scalar = instruction.getScalar( 1 );
				processString( program, instruction, 1, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.equals( "const_class" ) ) {
				Scalar scalar = instruction.getScalar( 1 );
				processClass( program, instruction, 1, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.equals( "instance_of" ) ) {
				Scalar scalar = instruction.getScalar( 2 );
				processClass( program, instruction, 2, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.equals( "check_cast" ) ) {
				Scalar scalar = instruction.getScalar( 1 );
				processClass( program, instruction, 1, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.startsWith( "invoke" ) ) {
				Scalar scalar = instruction.getScalar( 0 );//method id
				processMethod( program, instruction, 0, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.equals( "new_instance" ) ) {
				Scalar scalar = instruction.getScalar( 1 );
				processClass( program, instruction, 1, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.equals( "new_array" ) ) {
				Scalar scalar = instruction.getScalar( 2 );
				processClass( program, instruction, 2, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.startsWith( "iget" ) ) {
				Scalar scalar = instruction.getScalar( 2 );
				processField( program, instruction, 2, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.startsWith( "iput" ) ) {
				Scalar scalar = instruction.getScalar( 2 );
				processField( program, instruction, 2, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.startsWith( "sget" ) ) {
				Scalar scalar = instruction.getScalar( 1 );
				processField( program, instruction, 1, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.startsWith( "sput" ) ) {
				Scalar scalar = instruction.getScalar( 1 );
				processField( program, instruction, 1, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.startsWith( "filled_new_array" ) ) {
				Scalar scalar = instruction.getScalar( 0 );
				processClass( program, instruction, 0, header, ( int ) scalar.getUnsignedValue( ), log );
			}
			else if ( mnemonicString.startsWith( "fill_array_data" ) ) {
				Scalar scalar = instruction.getScalar( 1 );
				Address address = instruction.getMinAddress( ).add( scalar.getUnsignedValue( ) * 2 );
				if ( program.getMemory( ).getShort( address ) != FilledArrayDataPayload.MAGIC ) {
					log.appendMsg( "invalid filled array at " + address );
				}
				else {
					reader.setPointerIndex( address.getOffset( ) );
					FilledArrayDataPayload payload = new FilledArrayDataPayload( reader );
					DataType dataType = payload.toDataType( );
					createData( program, address, dataType );
					program.getReferenceManager( ).addMemoryReference( instruction.getMinAddress( ), address, RefType.DATA, SourceType.ANALYSIS, 1 );
				}
			}
		}
		return true;
	}

	@Override
	public boolean canAnalyze( Program program ) {
		ByteProvider provider = new MemoryByteProvider( program.getMemory( ), program.getMinAddress( ) );
		return DexConstants.isDexFile( provider );
	}

	@Override
	public AnalyzerType getAnalysisType( ) {
		return AnalyzerType.INSTRUCTION_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement( Program program ) {
		return true;
	}

	@Override
	public String getDescription( ) {
		return "Android DEX Instruction Markup";
	}

	@Override
	public String getName( ) {
		return "Android DEX Instruction Markup";
	}

	@Override
	public AnalysisPriority getPriority( ) {
		return new AnalysisPriority( 4 );
	}

	@Override
	public boolean isPrototype( ) {
		return false;
	}

	private String getClassName( Program program, DexHeader header, int classTypeIndex, MessageLog log ) {
		TypeIDItem typeItem = header.getTypes( ).get( classTypeIndex );
		StringIDItem stringItem = header.getStrings( ).get( typeItem.getDescriptorIndex( ) );
		return stringItem.getStringDataItem( ).getString( );
	}

	private String format( String className, String methodName ) {
		StringBuilder builder = new StringBuilder( );
		if ( className.startsWith( "L" ) && className.endsWith( ";" ) ) {
			String str = className.substring( 1, className.length( ) - 1 );
			StringTokenizer tokenizer = new StringTokenizer( str, "/" );
			while ( tokenizer.hasMoreTokens( ) ) {
				String token = tokenizer.nextToken( );
				builder.append( token + "::" );
			}
		}
		builder.append( methodName );
		return builder.toString( );
	}

	private void setEquate( Program program, Address address, int operand, String equateName, int equateValue ) {
		EquateTable equateTable = program.getEquateTable( );
		Equate equate = equateTable.getEquate( equateName );
		if ( equate == null ) {
			try {
				equate = equateTable.createEquate( equateName, equateValue );
			}
			catch ( Exception e ) {
				// ignore
			}
		}
		if ( equate == null ) {// happens when equate name is invalid
			return;
		}
		if ( equate.getValue( ) != equateValue ) {// verify value is same
			setEquate( program, address, operand, equateName + "_" + equateValue, equateValue );
			return;
		}
		equate.addReference( address, operand );
	}

	private void processMethod( Program program, Instruction instruction, int operand, DexHeader header, int methodIndex, MessageLog log ) {
		if ( methodIndex < 0 || methodIndex > header.getMethodIdsSize() ) {
			log.appendMsg( "method index not found: " + methodIndex );
			return;
		}

		//MethodIDItem methodIDItem = methods.get( methodIndex );

		//StringIDItem stringItem = header.getStrings( ).get( methodIDItem.getNameIndex( ) );
		//String methodName = stringItem.getStringDataItem( ).getString( );

		//String className = getClassName( program, header, methodIDItem.getClassIndex( ), log );

		//String valueName = format( className, methodName );

		Address methodIndexAddress = header.getMethodAddress( program, methodIndex );
		if (methodIndexAddress != Address.NO_ADDRESS)
			program.getReferenceManager().addMemoryReference( instruction.getMinAddress(), methodIndexAddress, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, operand );
	}

	private void processClass( Program program, Instruction instruction, int operand, DexHeader header, int classTypeIndex, MessageLog log ) {
		TypeIDItem typeItem = header.getTypes( ).get( classTypeIndex );
		StringIDItem stringItem = header.getStrings( ).get( typeItem.getDescriptorIndex( ) );
		String className = stringItem.getStringDataItem( ).getString( );

		setEquate( program, instruction.getMinAddress( ), operand, className, classTypeIndex );
		program.getListing( ).setComment( instruction.getMinAddress( ), CodeUnit.EOL_COMMENT, className );
	}

	private void processString( Program program, Instruction instruction, int operand, DexHeader header, int stringIndex, MessageLog log ) {
		List< StringIDItem > strings = header.getStrings( );
		if ( stringIndex < 0 || stringIndex > strings.size( ) ) {
			log.appendMsg( "string index not found: " + stringIndex );
			return;
		}
		StringIDItem stringIDItem = strings.get( stringIndex );
		StringDataItem stringDataItem = stringIDItem.getStringDataItem( );
		if ( stringDataItem == null ) {
			log.appendMsg( "string data item is null: " + stringIndex );
			return;
		}
		AddressSpace defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
		Address stringAddr = defaultAddressSpace.getAddress(stringIDItem.getStringDataOffset());
		program.getReferenceManager().addMemoryReference(instruction.getMinAddress(), stringAddr,
			RefType.DATA, SourceType.ANALYSIS, operand);
//		setEquate( program, instruction.getMinAddress( ), operand, stringDataItem.getString( ), stringIndex );
//		program.getListing( ).setComment( instruction.getMinAddress( ), CodeUnit.EOL_COMMENT, stringDataItem.getString( ) );
	}

	private void processField( Program program, Instruction instruction, int operand, DexHeader header, int fieldIndex, MessageLog log ) {
		List< FieldIDItem > fields = header.getFields( );

		if ( fieldIndex < 0 || fieldIndex > fields.size( ) ) {
			log.appendMsg( "field index not found: " + fieldIndex );
			return;
		}

		FieldIDItem fieldIDItem = fields.get( fieldIndex );

		StringIDItem stringItem = header.getStrings( ).get( fieldIDItem.getNameIndex( ) );
		String fieldName = stringItem.getStringDataItem( ).getString( );

		String className = getClassName( program, header, fieldIDItem.getClassIndex( ), log );
		String valueName = format( className, fieldName );

		setEquate( program, instruction.getMinAddress( ), operand, fieldName, fieldIndex );
		program.getListing( ).setComment( instruction.getMinAddress( ), CodeUnit.EOL_COMMENT, valueName );
	}
}
