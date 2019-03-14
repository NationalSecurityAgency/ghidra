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
package ghidra.file.formats.zlib;

import ghidra.app.util.bin.ByteProvider;

import java.io.*;
import java.util.Arrays;
import java.util.zip.*;

/**
 * 
 * TODO make this more memory efficient!!
 *
 */
public class ZLIB {
	
	public static final byte [] ZLIB_COMPRESSION_BEST    = new byte [] { (byte)0x78, (byte)0xda };
	public static final byte [] ZLIB_COMPRESSION_DEFAULT = new byte [] { (byte)0x78, (byte)0x9c };
	public static final byte [] ZLIB_COMPRESSION_NO_LOW  = new byte [] { (byte)0x78, (byte)0x01 };

	public ZLIB() {
	}

	/**
	 * Creates a new decompressor. 
	 * If the parameter 'nowrap' is true then the ZLIB header and checksum fields will not be used. 
	 * This provides compatibility with the compression format used by both GZIP and PKZIP.
	 * Note: When using the 'nowrap' option it is also necessary to provide an extra "dummy" byte as input. 
	 * This is required by the ZLIB native library in order to support certain optimizations.
	 * @param compressedIn an input stream containing the compressed data
	 * @param expectedDecompressedLength the expected length of the decompressed data
	 * @return an output stream containing the decompressed data
	 * @throws IOException
	 */
	public ByteArrayOutputStream decompress( InputStream compressedIn, int expectedDecompressedLength ) throws IOException {
		return decompress( compressedIn, expectedDecompressedLength, false );
	}

	/**
	 * Creates a new decompressor. 
	 * If the parameter 'noWrap' is true then the ZLIB header and checksum fields will not be used. 
	 * This provides compatibility with the compression format used by both GZIP and PKZIP.
	 * Note: When using the 'noWrap' option it is also necessary to provide an extra "dummy" byte as input. 
	 * This is required by the ZLIB native library in order to support certain optimizations.
	 * @param compressedIn an input stream containing the compressed data
	 * @param expectedDecompressedLength the expected length of the decompressed data
	 * @param noWrap if true then support GZIP compatible compression
	 * @return an output stream containing the decompressed data
	 * @throws IOException
	 */
	public ByteArrayOutputStream decompress( InputStream compressedIn, int expectedDecompressedLength, boolean noWrap ) throws IOException {

    	byte [] compressedBytes = convertInputStreamToByteArray( compressedIn );

        ByteArrayOutputStream decompressedBOS = new ByteArrayOutputStream();

    	byte [] tempDecompressedBytes = new byte[ 0x10000 ];

    	int totalDecompressed = 0;
        int offset = 0;

        try {
        	while ( offset < compressedBytes.length && totalDecompressed < expectedDecompressedLength ) {

        		if ( !noWrap && compressedBytes [ offset ] != 0x78 ) {
        			break;
        		}

                Inflater inflater = new Inflater( noWrap );

                inflater.setInput( compressedBytes, offset, compressedBytes.length - offset );

        		int nDecompressed = inflater.inflate( tempDecompressedBytes );

        		if ( nDecompressed == 0 ) {
        			break;
        		}

        		totalDecompressed += nDecompressed;

        		decompressedBOS.write( tempDecompressedBytes, 0, nDecompressed );

        		offset += inflater.getTotalIn();//increment total compressed bytes consumed
        	}
        }
        catch ( DataFormatException e ) {
        	throw new IOException( e.getMessage() );
        }

        return decompressedBOS;
    }

	/**
	 * Converts the contents of an input stream to a byte array
	 * @param compressedIn
	 * @return
	 * @throws IOException
	 */
	private byte [] convertInputStreamToByteArray( InputStream compressedIn ) throws IOException {
		byte [] bytes = new byte[ 8096 ];
    	ByteArrayOutputStream compressedBOS = new ByteArrayOutputStream();
    	while ( true ) {
    		int nRead = compressedIn.read( bytes );
    		if ( nRead == -1 ) {
    			break;
    		}
    		compressedBOS.write( bytes, 0, nRead );
    	}
    	return compressedBOS.toByteArray();
	}

	/**
	 * Creates a new compressor. 
	 * If 'noWrap' is true then the ZLIB header and checksum fields will not be used in order 
	 * to support the compression format used in both GZIP and PKZIP.
	 * @param decompressedBytes the decompressed bytes
	 * @return an output stream containing the compressed data
	 * @throws IOException
	 */
	public ByteArrayOutputStream compress( byte [] decompressedBytes ) throws IOException {
		return compress( false, decompressedBytes );
	}

	/**
	 * Creates a new compressor. 
	 * If 'noWrap' is true then the ZLIB header and checksum fields will not be used in order 
	 * to support the compression format used in both GZIP and PKZIP.
	 * @param noWrap if true then use GZIP compatible compression
	 * @param decompressedBytes the decompressed bytes
	 * @return an output stream containing the compressed data
	 * @throws IOException
	 */
	public ByteArrayOutputStream compress( boolean noWrap, byte [] decompressedBytes ) throws IOException {
        ByteArrayOutputStream compressedBOS = new ByteArrayOutputStream();

       	byte [] tempBuffer = new byte[ 0x10000 ];

        int offset = 0;

    	while ( offset < decompressedBytes.length ) {

            Deflater deflater = new Deflater( 0, noWrap );

           	deflater.setInput( decompressedBytes, offset, decompressedBytes.length - offset );

           	deflater.finish();

            if ( deflater.needsInput() ) {
            	System.out.println( "needs input??" );
            }

            int nDeflated = deflater.deflate( tempBuffer );

            if ( nDeflated == 0 ) {
            	break;
            }

            compressedBOS.write( tempBuffer, 0, nDeflated );

            offset += deflater.getTotalIn();
    	}

        return compressedBOS;
	}

	public final static boolean isZLIB( ByteProvider provider ) {
		try {
			byte [] bytes = provider.readBytes( 0, 2  );
			if ( Arrays.equals( bytes, ZLIB_COMPRESSION_NO_LOW ) ) {
				return true;
			}
			if ( Arrays.equals( bytes, ZLIB_COMPRESSION_DEFAULT ) ) {
				return true;
			}
			if ( Arrays.equals( bytes, ZLIB_COMPRESSION_BEST ) ) {
				return true;
			}
		}
		catch (Exception e) {
		}
		return false;
	}
}
