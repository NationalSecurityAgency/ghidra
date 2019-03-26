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

import ghidra.app.util.bin.BinaryReader;

import java.io.IOException;

public final class NSObjectParser {

	public static NSObject parseObject( BinaryReader reader, int objectOffset, BinaryPropertyListTrailer trailer ) throws IOException {

		reader.setPointerIndex( objectOffset );

		byte objectDescriptor = reader.readNextByte( );

		int objectType = ( objectDescriptor & 0xf0 ) >> 4;
		int objectInfo = ( objectDescriptor & 0x0f );

		switch ( objectType ) {
			case 0x0: { // simple
				switch ( objectInfo ) {
					case 0x0: { // NULL object
						return null;
					}
					case 0x8: { // false
						return new NSNumber( false );
					}
					case 0x9: { // TRUE
						return new NSNumber( true );
					}
					case 0xc: { // URL w/o base URL TODO
						return null;
					}
					case 0xd: { // URL w/ base URL TODO
						return null;
					}
					case 0xe: { // 16 byte UUID TODO
						return null;
					}
					case 0xf: { // filler byte
						return null;
					}
					default: {
						throw new IOException( "WARNING: The binary PLIST contains unknown SIMPLE object type: " + objectInfo );
					}
				}
			}
			case 0x1: { // integer
				int length = (int ) Math.pow( 2, objectInfo );
				switch ( length ) {
					case 1: {
						byte value = reader.readByte( objectOffset + 1 );
						return new NSNumber( value );
					}
					case 2: {
						short value = reader.readShort( objectOffset + 1 );
						return new NSNumber( value );
					}
					case 4: {
						int value = reader.readInt( objectOffset + 1 );
						return new NSNumber( value );
					}
					case 8: {
						long value = reader.readLong( objectOffset + 1 );
						return new NSNumber( value );
					}
				}
				throw new IOException( "WARNING: Invalid integer length specified in the binary PList." );
			}
			case 0x2: { // real
				int length = (int ) Math.pow( 2, objectInfo );
				if ( length == 4 ) {
					int intValue = reader.readInt( objectOffset + 1 );
					float floatValue = Float.intBitsToFloat( intValue );
					return new NSNumber( floatValue );
				}
				else if ( length == 8 ) {
					long longValue = reader.readLong( objectOffset + 1 );
					double doubleValue = Double.longBitsToDouble( longValue );
					return new NSNumber( doubleValue );
				}
				else {
					throw new IOException( "WARNING: Invalid real number length specified in the binary PList." );
				}
			}
			case 0x3: { // date
				if ( objectInfo != 3 ) {
					throw new IOException( "WARNING: Binary PLIST contains unknown date type:" + objectInfo );
				}
				long longValue = reader.readLong( objectOffset + 1 );
				double doubleValue = Double.longBitsToDouble( longValue );
				return new NSDate( doubleValue );
			}
			case 0x4: { // data
				int length = parseLength( reader, objectInfo );
				return new NSData( reader.readNextByteArray( length ) );
			}
			case 0x5: { // ascii string
				int length = parseLength( reader, objectInfo );
				return new NSString( reader.readNextAsciiString( length ), NSStringTypes.TYPE_ASCII );
			}
			case 0x6: { // utf-16-be string
				int length = parseLength( reader, objectInfo );
				return new NSString( reader.readNextUnicodeString( length ), NSStringTypes.TYPE_UTF16BE );
			}
			case 0x8: { // UID
				int length = reader.readNextByte( ) & 0xff;
				return new UID( reader.readNextByteArray( length ) );
			}
			case 0xa: { // array
				int length = parseLength( reader, objectInfo );
				NSArray array = new NSArray( trailer.getObjectRefSize( ) );
				for ( int i = 0 ; i < length ; ++i ) {
					if ( trailer.getObjectRefSize( ) == 1 ) {
						int value = reader.readNextByte( ) & 0xff;
						array.add( value );
					}
					else if ( trailer.getObjectRefSize( ) == 2 ) {
						int value = reader.readNextShort( ) & 0xffff;
						array.add( value );
					}
					else if ( trailer.getObjectRefSize( ) == 4 ) {
						int value = reader.readNextInt( );
						array.add( value );
					}
					else {
						throw new RuntimeException( "Invalid offset size in binary PList" );
					}
				}
				return array;
			}
			case 0xb: { // ordered set
				int length = parseLength( reader, objectInfo );
				NSSet set = new NSSet( true, trailer.getObjectRefSize( ) );
				for ( int i = 0 ; i < length ; i++ ) {
					if ( trailer.getObjectRefSize( ) == 1 ) {
						int value = reader.readNextByte( ) & 0xff;
						set.add( value );
					}
					else if ( trailer.getObjectRefSize( ) == 2 ) {
						int value = reader.readNextShort( ) & 0xffff;
						set.add( value );
					}
					else if ( trailer.getObjectRefSize( ) == 4 ) {
						int value = reader.readNextInt( );
						set.add( value );
					}
					else {
						throw new RuntimeException( "Invalid offset size in binary PList" );
					}
				}
				return set;
			}
			case 0xc: { // set
				int length = parseLength( reader, objectInfo );
				NSSet set = new NSSet( false, trailer.getObjectRefSize( ) );
				for ( int i = 0 ; i < length ; i++ ) {
					if ( trailer.getObjectRefSize( ) == 1 ) {
						int value = reader.readNextByte( ) & 0xff;
						set.add( value );
					}
					else if ( trailer.getObjectRefSize( ) == 2 ) {
						int value = reader.readNextShort( ) & 0xffff;
						set.add( value );
					}
					else if ( trailer.getObjectRefSize( ) == 4 ) {
						int value = reader.readNextInt( );
						set.add( value );
					}
					else {
						throw new RuntimeException( "Invalid offset size in binary PList" );
					}
				}
				return set;
			}
			case 0xd: { // dictionary
				int length = parseLength( reader, objectInfo );
				NSDictionary dictionary = new NSDictionary( trailer.getObjectRefSize( ) );
				for ( int i = 0 ; i < length ; ++i ) {
					if ( trailer.getObjectRefSize( ) == 1 ) {
						int key = reader.readNextByte( ) & 0xff;
						int value = reader.readNextByte( ) & 0xff;
						dictionary.put( key, value );
					}
					else if ( trailer.getObjectRefSize( ) == 2 ) {
						int key = reader.readNextShort( ) & 0xffff;
						int value = reader.readNextShort( ) & 0xffff;
						dictionary.put( key, value );
					}
					else if ( trailer.getObjectRefSize( ) == 4 ) {
						int key = reader.readNextInt( );
						int value = reader.readNextInt( );
						dictionary.put( key, value );
					}
					else {
						throw new RuntimeException( "Invalid offset size in binary PList" );
					}
				}
				return dictionary;
			}
			default: {
				throw new IOException( "WARNING: The binary PLIST contains unknown object type: " + objectType );
			}
		}
	}

	private static int parseLength( BinaryReader reader, int objectInfo ) throws IOException {
		int length = objectInfo;
		if ( objectInfo == 0xf ) {// longer than 0xf bytes...
			int offset = reader.readNextByte( ) & 0xff;
			if ( offset == 0x10 ) {
				length = reader.readNextByte( ) & 0xff;
			}
			else if ( offset == 0x11 ) {
				length = reader.readNextShort( ) & 0xffff;
			}
			else {
				throw new RuntimeException( );
			}
		}
		return length;
	}
}
