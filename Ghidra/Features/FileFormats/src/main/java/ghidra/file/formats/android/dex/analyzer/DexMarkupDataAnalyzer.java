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

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.file.formats.android.dex.format.DexConstants;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class DexMarkupDataAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze( Program program, AddressSetView set, TaskMonitor monitor, MessageLog log ) throws Exception {
		monitor.setMaximum( set == null ? program.getMemory( ).getSize( ) : set.getNumAddresses( ) );
		monitor.setProgress( 0 );

		DexAnalysisState analysisState = DexAnalysisState.getState(program);
		DexHeader header = analysisState.getHeader();

		int headerLength = header.toDataType( ).getLength( );

		Listing listing = program.getListing( );

		DataIterator dataIterator = listing.getDefinedData( set, true );
		while ( dataIterator.hasNext( ) ) {
			monitor.checkCanceled( );
			monitor.incrementProgress( 1 );

			Data data = dataIterator.next( );

			if ( data.getMinAddress( ).getOffset( ) == 0x0 ) {
				continue;// skip the main dex header..
			}

			monitor.setMessage( "DEX: Data markup ... " + data.getMinAddress( ) );

			if ( data.isStructure( ) ) {
				processData( data, headerLength, monitor );
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
		return AnalyzerType.DATA_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement( Program program ) {
		return true;
	}

	@Override
	public String getDescription( ) {
		return "Android DEX Data Markup";
	}

	@Override
	public String getName( ) {
		return "Android DEX Data Markup";
	}

	@Override
	public AnalysisPriority getPriority( ) {
		return new AnalysisPriority( 5 );
	}

	@Override
	public boolean isPrototype( ) {
		return false;
	}

	private void processData( Data data, int headerLength, TaskMonitor monitor ) throws Exception {
		for ( int i = 0 ; i < data.getNumComponents( ) ; ++i ) {
			monitor.checkCanceled( );
			Data component = data.getComponent( i );
			if ( component.getNumComponents( ) > 0 ) {
				processData( component, headerLength, monitor );
			}
			if ( component.getReferencesFrom( ).length > 0 ) {
				continue;
			}
			if ( component.getFieldName( ).toLowerCase( ).indexOf( "offset" ) != -1 ) {
				Scalar scalar = component.getScalar( 0 );
				if ( scalar.getUnsignedValue( ) < headerLength ) {// skip low number points into dex header
					continue;
				}
				Address destination = component.getMinAddress( ).getNewAddress( scalar.getUnsignedValue( ) );
				Program program = component.getProgram( );
				ReferenceManager referenceManager = program.getReferenceManager( );
				referenceManager.addMemoryReference( component.getMinAddress( ), destination, RefType.DATA, SourceType.ANALYSIS, 0 );
			}
		}
	}
}
