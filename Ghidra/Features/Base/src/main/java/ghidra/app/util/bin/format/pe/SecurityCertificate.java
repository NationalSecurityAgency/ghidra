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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.*;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.DuplicateNameException;

/**
 * A class to represent the <code>WIN_CERTIFICATE</code>
 * struct as defined in <b><code>winbase.h</code></b>.
 * <p>
 * This structure encapsulates a signature used in verifying executables.
 * <p>
 * <pre>
 * typedef struct _WIN_CERTIFICATE {
 *     DWORD       dwLength;
 *     WORD        wRevision;
 *     WORD        wCertificateType;   // WIN_CERT_TYPE_xxx
 *     BYTE        bCertificate[ANYSIZE_ARRAY];
 * } WIN_CERTIFICATE, *LPWIN_CERTIFICATE;
 * </pre> 
 * 
 * 
 */
public class SecurityCertificate implements StructConverter {
	/**
	 * The name to use when converting into a structure data type.
	 */
	public final static String NAME = "WIN_CERTIFICATE";

    //
    // Currently, the only defined certificate revision is WIN_CERT_REVISION_1_0
    //
    public final static int WIN_CERT_REVISION_1_0 = 0x0100;
    public final static int WIN_CERT_REVISION_2_0 = 0x0200;

    //
    // Possible certificate types are specified by the following values
    //
    /**
     * bCertificate contains an X.509 Certificate.
     */
    public final static int WIN_CERT_TYPE_X509             = 0x0001;
    /**
     * bCertificate contains a PKCS SignedData structure.
     */
    public final static int WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;
    /**
     * Reserved.
     */
    public final static int WIN_CERT_TYPE_RESERVED_1       = 0x0003;
    /**
     * bCertificate contains PKCS1_MODULE_SIGN fields.
     */
    public final static int WIN_CERT_TYPE_PKCS1_SIGN      = 0x0009;

    private int dwLength;
    private short wRevision;
    private short wCertificateType;
    private byte [] bCertificate;

	/**
	 * Read a SecurityCertificate.
	 * 
	 * @param reader BinaryReader to use
	 * @param index offset where the SecurityCertificate starts
	 * @param sizeLimit maximum number of bytes that can be read from the reader
	 * @return new SecurityCertificate, or null if invalid or bad data
	 * @throws IOException if io error when reading data
	 */
	static SecurityCertificate read(BinaryReader reader, long index, int sizeLimit)
			throws IOException {
		if (sizeLimit < 8) {
			return null;
		}
		reader = reader.clone(index);

		SecurityCertificate result = new SecurityCertificate();
		result.dwLength = reader.readNextInt();
		result.wRevision = reader.readNextShort();
		result.wCertificateType = reader.readNextShort();

		if (result.dwLength < 8 || sizeLimit < result.dwLength) {
			return null;
		}

		int certByteCount = result.dwLength - 4 - 2 - 2;
		result.bCertificate = reader.readNextByteArray(certByteCount);

		return result;
	}

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public SecurityCertificate() {}

	int getNumberOfBytesConsumed() {
		return (int) NumericUtilities.getUnsignedAlignedValue(dwLength, 8);
	}

	/**
	 * Returns the length, in bytes, of the signature.
	 * @return the length, in bytes, of the signature
	 */
    public int getLength() {
        return dwLength;
    }

	/**
	 * Returns the certificate revision. Currently, 
	 * the only defined certificate revision is 
	 * WIN_CERT_REVISION_1_0 (0x0100). 
	 * @return the certificate revision
	 */
    public int getRevision() {
        return wRevision;
    }

	/**
	 * Returns the certificate type.
	 * @return the certificate type
	 */
    public int getType()  {
        return wCertificateType;
    }

	/**
	 * Returns a string representation of the certificate type.
	 * @return a string representation of the certificate type
	 */
    public String getTypeAsString() {
        switch (wCertificateType) {
            case WIN_CERT_TYPE_X509:
                return "X.509";
            case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
                return "PKCS Signed";
//todo:
//locate...
//            case WIN_CERT_TYPE_TS_STACK_SIGNED:
//                return "TS Stack Signed";
            case WIN_CERT_TYPE_RESERVED_1:
                return "Reserved";
            default:
                return "Unknown Certificate Type";
        }
    }

	/**
	 * An array of certificates. The format of this member 
	 * depends on the value of wCertificateType.
	 * @return an array of certificates
	 */
    public byte [] getData() {
        return bCertificate;
    }

    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
	public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME+"_"+dwLength, 0);
        struct.add(DWORD,"dwLength",null);
        struct.add( WORD,"wRevision",null);
        struct.add( WORD,"wCertificateType",getTypeAsString());

        if ( bCertificate != null && bCertificate.length > 0 ) {
	    	DataType array = new ArrayDataType(BYTE, bCertificate.length, 1);
	        struct.add(array,"bCertificate",null);
        }

        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }
}
