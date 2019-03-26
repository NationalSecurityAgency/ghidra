/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
//Splits a PEF file that contains multiple containers
//into separate files containing only one container.
//The name of the file will be the container
//name defined in the AppleSingleDouble (.) file.
//@category Binary

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.RandomAccessByteProvider;
import ghidra.app.util.bin.format.macos.asd.*;
import ghidra.app.util.bin.format.macos.cfm.CFragResource;
import ghidra.app.util.bin.format.macos.cfm.CFragResourceMember;
import ghidra.app.util.bin.format.macos.rm.*;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.Msg;

import java.io.*;
import java.util.List;

public class SplitMultiplePefContainersScript extends GhidraScript {
	private static final int BUFFER = 4096;

	@Override
	public void run() throws Exception {
		File pefFile = askFile("Select PEF File", "OK");

		File resourceForkFile = getResourceFork(pefFile);

		File outputDirectory = askDirectory("Select Output Directory", "OK");

		if (pefFile.getParentFile().equals(outputDirectory)) {
			popup("Output directory must be different from source directory.");
			return;
		}

		RandomAccessByteProvider pefProvider = open(pefFile);
		RandomAccessByteProvider resourceForkProvider = open(resourceForkFile);

		try {
			ResourceHeader resourceHeader = findResourceFork(resourceForkProvider);
			if (resourceHeader == null) {
				popup("File does not contain a resource fork: " + resourceForkFile.getName());
				return;
			}

			CFragResource cFragResource = findCodeFragmentManager(resourceHeader);
			if (cFragResource == null) {
				popup("File does not a Code Fragment Manager: " + resourceForkFile.getName());
				return;
			}

			List<CFragResourceMember> members = cFragResource.getMembers();

			for (CFragResourceMember member : members) {
				if (monitor.isCancelled()) {
					break;
				}

				File memberFile = new File(outputDirectory, member.getName());

				if (memberFile.exists()) {
					boolean overwrite =
						askYesNo("File Already Exists", memberFile.getAbsolutePath() +
							"\nOverwrite?");
					if (!overwrite) {
						continue;
					}
				}

				writeFile(member, memberFile, pefProvider);
			}
		}
		finally {
			close(pefProvider);
			close(resourceForkProvider);
		}
	}

	private File getResourceFork(File pefFile) {
		if (isRunningOnMac()) {
			return new File(pefFile.getParentFile(), pefFile.getName() + "/..namedfork/rsrc");
		}
		return new File(pefFile.getParentFile(), "._" + pefFile.getName());
	}

	private void writeFile(CFragResourceMember member, File memberFile, ByteProvider provider)
			throws IOException {
		OutputStream out = new FileOutputStream(memberFile);
		int offset = member.getOffset();
		int length = member.getLength();
		try {
			for (int i = offset; i < offset + length; i += BUFFER) {
				if (i + BUFFER < offset + length) {
					out.write(provider.readBytes(i, BUFFER));
				}
				else {
					out.write(provider.readBytes(i, offset + length - i));
				}
			}
		}
		finally {
			out.close();
		}
	}

	private CFragResource findCodeFragmentManager(ResourceHeader header) {
		ResourceMap map = header.getMap();
		List<ResourceType> resourceTypeList = map.getResourceTypeList();
		for (ResourceType type : resourceTypeList) {
			if (type.getType() == ResourceTypes.TYPE_CFRG) {
				return (CFragResource) type.getResourceObject();
			}
		}
		return null;
	}

	private ResourceHeader findResourceFork(RandomAccessByteProvider resourceForkProvider)
			throws Exception {
		if (isRunningOnMac()) {
			return new ResourceHeader(resourceForkProvider);
		}

		AppleSingleDouble appleHeader = new AppleSingleDouble(resourceForkProvider);

		List<EntryDescriptor> entryList = appleHeader.getEntryList();
		for (EntryDescriptor entry : entryList) {
			if (entry.getEntryID() == EntryDescriptorID.ENTRY_RESOURCE_FORK) {
				return (ResourceHeader) entry.getEntry();
			}
		}
		return null;
	}

	private RandomAccessByteProvider open(File file) {
		try {
			return new RandomAccessByteProvider(file);
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
		return null;
	}

	private void close(RandomAccessByteProvider provider) {
		try {
			if (provider != null) {
				provider.close();
			}
		}
		catch (IOException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
		}
	}

	private boolean isRunningOnMac() {
		return Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X;
	}

}
