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
package ghidra.file.formats.ext4;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Program;

class MultiProgramMemoryByteProvider implements ByteProvider {

	private Program [] programs;
	private Address [] baseAddresses;

	MultiProgramMemoryByteProvider( Program program1 ) {
		checkPrograms( );
		programs = new Program [] {
			program1
		};
		baseAddresses = new Address[] {
				program1.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( 0 ),
		};
	}
	MultiProgramMemoryByteProvider( Program program1, Program program2 ) {
		checkPrograms( );
		programs = new Program [] {
			program1,
			program2,
		};
		baseAddresses = new Address[] {
				program1.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( 0 ),
				program2.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( 0 ),
		};
	}
	MultiProgramMemoryByteProvider( Program program1, Program program2, Program program3 ) {
		checkPrograms( );
		programs = new Program [] {
			program1,
			program2,
			program3,
		};
		baseAddresses = new Address[] {
				program1.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( 0 ),
				program2.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( 0 ),
				program3.getAddressFactory( ).getDefaultAddressSpace( ).getAddress( 0 ),
		};
	}

	/**
	 * TODO
	 * Check to make sure programs are disjoint and contiguous memory spaces.
	 */
	private void checkPrograms() {
		
	}

	@Override
	public File getFile( ) {
		if ( programs.length != 0 ) {
			return new File( programs[ 1 ].getExecutablePath( ) );
		}
		return null;
	}

	@Override
	public String getName( ) {
		if ( programs.length != 0 ) {
			return programs[ 1 ].getName( );
		}
		return null;
	}

	@Override
	public String getAbsolutePath( ) {
		if ( programs.length != 0 ) {
			return programs[ 1].getExecutablePath( );
		}
		return null;
	}

	@Override
	public long length( ) throws IOException {
		int length = 0;
		for ( Program program : programs ) {
			length += program.getMemory().getSize( );
		}
		return length;
	}

	@Override
	public boolean isValidIndex( long index ) {
		for ( int i = 0 ; i < programs.length ; ++i ) {
			try {
				Address indexAddress = baseAddresses[ i ].add( index );
				return programs[ i ].getMemory( ).contains( indexAddress );
			}
			catch (AddressOutOfBoundsException e) {
			}
		}
		return false;
	}

	@Override
	public void close( ) throws IOException {
		programs = null;
		baseAddresses = null;
	}

	@Override
	public byte readByte( long index ) throws IOException {
		for ( int i = 0 ; i < programs.length ; ++i ) {
			try {
				return programs[ i ].getMemory( ).getByte( baseAddresses[ i ].add( index ) );
			}
			catch ( Exception e ) {
			}
		}
		throw new IOException( "Unable to read byte at index: " + index );
	}

	@Override
	public byte [] readBytes( long index, long length ) throws IOException {
		for ( int i = 0 ; i < programs.length ; ++i ) {
			try {
				byte [] bytes = new byte[ (int) length ];
				int nRead = programs[ i ].getMemory( ).getBytes( baseAddresses[ i ].add( index ), bytes );
				if ( nRead != length ) {
					throw new IOException( "Unable to read " + length + " bytes at index " + index );
				}
				return bytes;
			}
			catch (Exception e) {
			}
		}
		throw new IOException( "Unable to read " + length + " bytes at index " + index );
	}

	@Override
	public InputStream getInputStream( long index ) throws IOException {
//		if ( index < program1.getMemory( ).getSize( ) ) {
//			return new MemoryByteProviderInputStream( program1.getMemory( ), baseAddress1.add( index ) );
//		}
//		return new MemoryByteProviderInputStream( program2.getMemory( ), baseAddress2.add( index ) );
		throw new UnsupportedOperationException( );
	}

}
