/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.zlib;

import java.io.*;
import java.util.zip.*;

/**
 * 
 * TODO make this more memory efficient!!
 *
 */
public class ZLIB {
	
    public ZLIB() {
	}

	public ByteArrayOutputStream decompress( InputStream compressedIn, int expectedDecompressedLength ) throws IOException {
		return decompress( compressedIn, expectedDecompressedLength, false );
	}

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

	public ByteArrayOutputStream compress(byte[] decompressedBytes) {
		return compress( false, decompressedBytes );
	}

	public ByteArrayOutputStream compress(boolean noWrap, byte[] decompressedBytes) {
        ByteArrayOutputStream compressedBOS = new ByteArrayOutputStream();

       	byte [] tempBuffer = new byte[ 0x10000 ];

        int offset = 0;

    	while ( offset < decompressedBytes.length ) {

            Deflater deflater = new Deflater( 0, noWrap );

           	deflater.setInput( decompressedBytes, offset, decompressedBytes.length - offset );

           	deflater.finish();

            if ( deflater.needsInput() ) {
            	System.err.println( "needs input??" );
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
}
