/* ###
 * IP: Apache License 2.0
 */
/*
 * Copyright (C) 2008 The Android Open Source Project
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

package ghidra.file.formats.android.dex.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import com.googlecode.d2j.DexException;

import ghidra.util.NumericUtilities;

/**
 * Reads and writes DWARFv3 LEB 128 signed and unsigned integers. See DWARF v3 section 7.6.
 */
public final class Leb128 {
	private Leb128() {
	}

	/**
	 * Gets the number of bytes in the unsigned LEB128 encoding of the given value.
	 * 
	 * @param value
	 *            the value in question
	 * @return its write size, in bytes
	 */
	public static int unsignedLeb128Size( int value ) {
		// TODO: This could be much cleverer.

		int remaining = value >> 7;
		int count = 0;

		while ( remaining != 0 ) {
			remaining >>= 7;
			count++;
		}

		return count + 1;
	}

	/**
	 * Gets the number of bytes in the signed LEB128 encoding of the given value.
	 * 
	 * @param value
	 *            the value in question
	 * @return its write size, in bytes
	 */
	public static int signedLeb128Size( int value ) {
		// TODO: This could be much cleverer.

		int remaining = value >> 7;
		int count = 0;
		boolean hasMore = true;
		int end = ( ( value & Integer.MIN_VALUE ) == 0 ) ? 0 : -1;

		while ( hasMore ) {
			hasMore = ( remaining != end ) || ( ( remaining & 1 ) != ( ( value >> 6 ) & 1 ) );

			value = remaining;
			remaining >>= 7;
			count++;
		}

		return count;

		// ByteArrayOutputStream out = new ByteArrayOutputStream( );
		// int remaining = value >>> 7;
		//
		// while ( remaining != 0 ) {
		// out.write( ( byte ) ( ( value & 0x7f ) | 0x80 ) );
		// value = remaining;
		// remaining >>>= 7;
		// }
		//
		// out.write( ( byte ) ( value & 0x7f ) );
		//
		// return out.toByteArray( ).length;
	}

	public static int readSignedLeb128( byte [] bytes ) {
		return readSignedLeb128( new ByteArrayInputStream( bytes ) );
	}

	/**
	 * Reads an signed integer from {@code in}.
	 */
	public static int readSignedLeb128( ByteArrayInputStream in ) {
		int result = 0;
		int cur;
		int count = 0;
		int signBits = -1;

		do {
			cur = in.read( ) & 0xff;
			result |= ( cur & 0x7f ) << ( count * 7 );
			signBits <<= 7;
			count++;
		}
		while ( ( ( cur & 0x80 ) == 0x80 ) && count < 5 );

		if ( ( cur & 0x80 ) == 0x80 ) {
			throw new DexException( "invalid LEB128 sequence" );
		}

		// Sign extend if appropriate
		if ( ( ( signBits >> 1 ) & result ) != 0 ) {
			result |= signBits;
		}

		return result;
	}

	public static int readUnsignedLeb128( byte [] bytes ) {
		return readUnsignedLeb128( new ByteArrayInputStream( bytes ) );
	}

	/**
	 * Reads an unsigned integer from {@code in}.
	 */
	public static int readUnsignedLeb128( ByteArrayInputStream in ) {
		int result = 0;
		int cur;
		int count = 0;

		do {
			cur = in.read( ) & 0xff;
			result |= ( cur & 0x7f ) << ( count * 7 );
			count++;
		}
		while ( ( ( cur & 0x80 ) == 0x80 ) && count < 5 );

		if ( ( cur & 0x80 ) == 0x80 ) {
			throw new DexException( "invalid LEB128 sequence" );
		}

		return result;
	}

	/**
	 * Writes {@code value} as an unsigned integer to {@code out}, starting at {@code offset}. Returns the number of bytes written.
	 */
	public static void writeUnsignedLeb128( ByteArrayOutputStream out, int value ) {
		int remaining = value >>> 7;

		while ( remaining != 0 ) {
			out.write( ( byte ) ( ( value & 0x7f ) | 0x80 ) );
			value = remaining;
			remaining >>>= 7;
		}

		out.write( ( byte ) ( value & 0x7f ) );
	}

	/**
	 * Writes {@code value} as a signed integer to {@code out}, starting at {@code offset}. Returns the number of bytes written.
	 */
	public static void writeSignedLeb128( ByteArrayOutputStream out, int value ) {
		int remaining = value >> 7;
		boolean hasMore = true;
		int end = ( ( value & Integer.MIN_VALUE ) == 0 ) ? 0 : -1;

		while ( hasMore ) {
			hasMore = ( remaining != end ) || ( ( remaining & 1 ) != ( ( value >> 6 ) & 1 ) );

			out.write( ( byte ) ( ( value & 0x7f ) | ( hasMore ? 0x80 : 0 ) ) );
			value = remaining;
			remaining >>= 7;
		}
	}

	public static void main( String [] args ) {

		//ByteArrayOutputStream out = new ByteArrayOutputStream( );
		//writeSignedLeb128( out, -12345 );

		//System.out.println( "array length: " + out.toByteArray( ).length );

		//System.out.println( "actual length: " + signedLeb128Size( -12345 ) );

		//System.out.println( readSignedLeb128( out.toByteArray( ) ) );

		System.out.println( readUnsignedLeb128( NumericUtilities.convertStringToBytes("807f" ) ) );

		
	}
}
