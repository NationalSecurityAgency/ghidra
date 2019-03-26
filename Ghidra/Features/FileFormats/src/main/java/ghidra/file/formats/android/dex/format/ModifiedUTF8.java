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

import java.io.*;

public final class ModifiedUTF8 {

	public final static String decode( InputStream in, char [] out ) throws UTFDataFormatException, IOException {
		int s = 0;
		while ( true ) {
			char a = ( char ) ( in.read( ) & 0xff );
			if ( a == 0 ) {
				return new String( out, 0, s );
			}
			out[ s ] = a;
			if ( a < '\u0080' ) {
				s++;
			}
			else if ( ( a & 0xe0 ) == 0xc0 ) {
				int b = in.read( ) & 0xff;
				if ( ( b & 0xC0 ) != 0x80 ) {
					throw new UTFDataFormatException( "bad second byte" );
				}
				out[ s++ ] = ( char ) ( ( ( a & 0x1F ) << 6 ) | ( b & 0x3F ) );
			}
			else if ( ( a & 0xf0 ) == 0xe0 ) {
				int b = in.read( ) & 0xff;
				int c = in.read( ) & 0xff;
				if ( ( ( b & 0xC0 ) != 0x80 ) || ( ( c & 0xC0 ) != 0x80 ) ) {
					throw new UTFDataFormatException( "bad second or third byte" );
				}
				out[ s++ ] = ( char ) ( ( ( a & 0x0F ) << 12 ) | ( ( b & 0x3F ) << 6 ) | ( c & 0x3F ) );
			}
			else {
				throw new UTFDataFormatException( "bad byte" );
			}
		}
	}
}
