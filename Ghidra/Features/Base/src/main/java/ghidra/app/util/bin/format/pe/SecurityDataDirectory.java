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
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.ByteArrayConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.DataConverter;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

// See https://docs.microsoft.com/en-us/windows/desktop/debug/pe-format

public class SecurityDataDirectory extends DataDirectory implements ByteArrayConverter {
    private final static String NAME = "IMAGE_DIRECTORY_ENTRY_SECURITY";

    private SecurityCertificate [] certificates;

    static SecurityDataDirectory createSecurityDataDirectory(
            NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
            throws IOException {
        SecurityDataDirectory securityDataDirectory = (SecurityDataDirectory) reader.getFactory().create(SecurityDataDirectory.class);
        securityDataDirectory.initSecurityDataDirectory(ntHeader, reader);
        return securityDataDirectory;
    }

    /**
     * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
     */
    public SecurityDataDirectory() {}

	private void initSecurityDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader) throws IOException {
		processDataDirectory(ntHeader, reader);

        if (certificates == null) {
			certificates = new SecurityCertificate[0];
		}
	}

	/**
	 * Returns an array of security certificates.
	 * @return an array of security certificates
	 */
	public SecurityCertificate [] getCertificate() {
		return certificates;
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException {

		if (!isBinary) {//certificates are never mapped into running program...
			return;
		}

		monitor.setMessage(program.getName()+": security data...");

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Address addr = space.getAddress(virtualAddress);//NOTE: virtualAddress is only a binary offset inside file!!!

		createDirectoryBookmark(program, addr);

		program.getListing().clearCodeUnits(addr, addr, false);

		for (SecurityCertificate cert : certificates) {
			DataType dt = cert.toDataType();
			program.getListing().createData(addr, dt);
			addr = addr.add(dt.getLength());
		}
	}

	@Override
	public boolean parse() throws IOException {
		List<SecurityCertificate> list = new ArrayList<>();

        // Sanity check...
        // Sometimes the cert address is not valid

        if (!reader.isValidIndex(getVirtualAddress())) {
            Msg.warn(this, "Certificate address is not valid.");
            return false;
        }

        // Note:
        // This data directory entry gives a file offset rather than an RVA

        int certOffset = getVirtualAddress();
        int certSize   = getSize();
		if (certOffset + certSize > reader.length()) {
			Msg.warn(this, "Certificate length " + certSize + " exceeds EOF.");
			return false;
		}

        while (certSize > 0 && certSize < NTHeader.MAX_SANE_COUNT) {
			SecurityCertificate cert = SecurityCertificate.read(reader, certOffset, certSize);
			if (cert == null) {
            	return false;
            }
            list.add(cert);

			int certBytesUsed = cert.getNumberOfBytesConsumed();
			certOffset += certBytesUsed;
			certSize -= certBytesUsed;
        }

        certificates = new SecurityCertificate[list.size()];
        list.toArray(certificates);
        return true;
    }
	
    /**
     * @see ghidra.app.util.bin.StructConverter#toDataType()
     */
    @Override
    public DataType toDataType() throws DuplicateNameException {
        StructureDataType struct = new StructureDataType(NAME, 0);
        for (SecurityCertificate certificate : certificates) {
            struct.add(certificate.toDataType());
        }
        struct.setCategoryPath(new CategoryPath("/PE"));
        return struct;
    }

	/**
	 * @see ghidra.app.util.bin.ByteArrayConverter#toBytes(ghidra.util.DataConverter)
	 */
	@Override
	public byte [] toBytes(DataConverter dc) {
		try {
			return reader.readByteArray( virtualAddress, size );
		}
		catch ( IOException e) {
		}
		return new byte[size];//TODO: need to implement!
	}

	/**
	 * @see ghidra.app.util.bin.format.pe.DataDirectory#writeBytes(java.io.RandomAccessFile, ghidra.util.DataConverter, ghidra.app.util.bin.format.pe.PortableExecutable)
	 */
	@Override
    public void writeBytes(RandomAccessFile raf, DataConverter dc, PortableExecutable template) 
		throws IOException {

		if (size == 0) {
			return;
		}

		DataDirectory [] originalDataDirs = template.getNTHeader().getOptionalHeader().getDataDirectories();
		if (originalDataDirs.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY) {
			if (originalDataDirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY] == null || 
				originalDataDirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY].getSize() == 0) {
				return;
			}
		}

		if (originalDataDirs.length > OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY) {
			SecurityDataDirectory originalSDD = (SecurityDataDirectory)originalDataDirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_SECURITY];
			raf.seek(rvaToPointer());
			raf.write(originalSDD.toBytes(dc));
		}
	}

	@Override
    int rvaToPointer() {
		return virtualAddress;
	}

	void updatePointers(int offset) {
		virtualAddress += offset;
	}

	/**
	 * virtualAddress is always a binary offset
	 */
	public Address getMarkupAddress(Program program, boolean isBinary) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress( virtualAddress);
	}
}
