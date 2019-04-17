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
package ghidra.file.formats.android.odex;

import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.file.analyzers.FileFormatAnalyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;

public class OdexHeaderFormatAnalyzer extends FileFormatAnalyzer {

	@Override
	public boolean analyze( Program program, AddressSetView set, TaskMonitor monitor, MessageLog log ) throws Exception {

		Address address = toAddr( program, 0x0 );

		if ( getDataAt( program, address ) != null ) {
			log.appendMsg( "data already exists." );
			return true;
		}

		Memory memory = program.getMemory( );
		MemoryBlock block = memory.getBlock( "ram" );
		block.setRead( true );
		block.setWrite( false );
		block.setExecute( false );

		ByteProvider provider = new MemoryByteProvider( program.getMemory( ), program.getMinAddress( ) );
		BinaryReader reader = new BinaryReader( provider, true );

		OdexHeader header = new OdexHeader( reader );

		DataType headerDataType = header.toDataType();
		createData( program, address, headerDataType);

		createFragment(program, "header", address, address.add(headerDataType.getLength()));

		Address dexAddress = toAddr(program, header.getDexOffset());
		createFragment(program, "dex", dexAddress, dexAddress.add(header.getDexLength()));

		Address depsAddress = toAddr(program, header.getDepsOffset());
		createFragment(program, "deps", depsAddress, depsAddress.add(header.getDepsLength()));
		processDeps( program, header, monitor, log );

		Address auxAddress = toAddr(program, header.getAuxOffset());
		createFragment(program, "aux", auxAddress, auxAddress.add(header.getAuxLength()));

		monitor.setMessage( "ODEX: cleaning up tree" );
		removeEmptyFragments( program );

		return true;
	}

	@Override
	public boolean canAnalyze( Program program ) {
		ByteProvider provider = new MemoryByteProvider( program.getMemory( ), program.getMinAddress( ) );
		return OdexConstants.isOdexFile( provider );
	}

	@Override
	public AnalyzerType getAnalysisType( ) {
		return AnalyzerType.BYTE_ANALYZER;
	}

	@Override
	public boolean getDefaultEnablement( Program program ) {
		return true;
	}

	@Override
	public String getDescription( ) {
		return "Android ODEX Header Format";
	}

	@Override
	public String getName( ) {
		return "Android ODEX Header Format";
	}

	@Override
	public AnalysisPriority getPriority( ) {
		return new AnalysisPriority( 0 );
	}

	@Override
	public boolean isPrototype( ) {
		return false;
	}

	private void processDeps(Program program, OdexHeader header,
			TaskMonitor monitor, MessageLog log) throws Exception {

		int depsOffset = header.getDepsOffset();
		int depsLength = header.getDepsLength();

		Address depsAddress = toAddr( program, depsOffset );
		Address depsEndAddress = depsAddress.add( depsLength );

		createData( program, depsAddress, new DWordDataType() );
		depsAddress = depsAddress.add( 4 );

		createData( program, depsAddress, new DWordDataType() );
		depsAddress = depsAddress.add( 4 );

		createData( program, depsAddress, new DWordDataType() );
		depsAddress = depsAddress.add( 4 );

		createData( program, depsAddress, new DWordDataType() );
		depsAddress = depsAddress.add( 4 );

		while ( depsAddress.compareTo(depsEndAddress) < 0 ) {
			monitor.checkCanceled();

			createData( program, depsAddress, new DWordDataType() );
			int stringLength = program.getMemory().getInt(depsAddress);
			depsAddress = depsAddress.add( 4 );

			program.getListing().createData(depsAddress, new StringDataType(), stringLength);
			depsAddress = depsAddress.add( stringLength );

			for ( int i = 0; i < 5; ++i ) {
				createData( program, depsAddress, new DWordDataType() );
				depsAddress = depsAddress.add( 4 );
			}
		}
	}

}
