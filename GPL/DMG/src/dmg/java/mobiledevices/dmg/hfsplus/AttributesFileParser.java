/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.hfsplus;

import java.io.*;
import java.util.HashMap;
import java.util.Map;

import org.catacombae.hfsexplorer.fs.ImplHFSXFileSystemView;
import org.catacombae.hfsexplorer.fs.NullProgressMonitor;
import org.catacombae.hfsexplorer.types.hfscommon.CommonHFSCatalogFile;
import org.catacombae.hfsexplorer.types.hfscommon.CommonHFSForkData;
import org.catacombae.hfsexplorer.types.hfsplus.*;
import org.catacombae.jparted.lib.fs.FSFile;
import org.catacombae.jparted.lib.fs.hfscommon.HFSCommonFSFile;
import org.catacombae.jparted.lib.fs.hfsx.HFSXFileSystemHandler;

import mobiledevices.dmg.btree.*;
import mobiledevices.dmg.decmpfs.DecmpfsHeader;
import mobiledevices.dmg.ghidra.GBinaryReader;
import mobiledevices.dmg.ghidra.GByteProvider;

/**
 * This code will extract the attributes file from the HFS+ file system,
 * which contains the B-tree for traversing the DECOMPFS files.
 */
public class AttributesFileParser {

	private Map<FSFile, DecmpfsHeader> map = new HashMap<FSFile, DecmpfsHeader>();
	private GByteProvider provider;
	private BTreeRootNodeDescriptor root;

	public AttributesFileParser( HFSXFileSystemHandler handler, String prefix ) throws IOException {

        ImplHFSXFileSystemView hfsxFileSystemView = (ImplHFSXFileSystemView) handler.getFSView();
        HFSPlusVolumeHeader volumeHeader = hfsxFileSystemView.getHFSPlusVolumeHeader();

        HFSPlusForkData attributes = volumeHeader.getAttributesFile();

       	File attributesFile = writeVolumeHeaderFile( hfsxFileSystemView, attributes, prefix + "_" + "attributesFile" );

		provider = new GByteProvider( attributesFile );

       	if ( attributesFile.length() == 0 ) {
       		return;
       	}

		GBinaryReader reader = new GBinaryReader( provider, false );

        root = new BTreeRootNodeDescriptor( reader );
	}

	public void dispose() throws IOException {
		map.clear();
		provider.close();
	}

	private int getFileID(FSFile file) {
		try {
		    HFSCommonFSFile hfsFile = (HFSCommonFSFile)file;
		    CommonHFSCatalogFile catalogFile = hfsFile.getInternalCatalogFile();
		    CommonHFSCatalogFile.HFSPlusImplementation hfsPlusCatalogFile = (CommonHFSCatalogFile.HFSPlusImplementation)catalogFile;
		    HFSPlusCatalogFile underlying = hfsPlusCatalogFile.getUnderlying();
		    HFSCatalogNodeID fileID = underlying.getFileID();
		    return fileID.toInt();
		}
		catch (Exception e) {
			return -1;
		}
	}

	private File writeVolumeHeaderFile( ImplHFSXFileSystemView hfsxFileSystemView, 
										HFSPlusForkData volumeHeaderFile, 
										String volumeHeaderFileName ) throws IOException {

		if (volumeHeaderFile == null) {
			return null;
		}

		File file = File.createTempFile( "Ghidra_" + volumeHeaderFileName + "_", ".tmp" );
		file.deleteOnExit();
		OutputStream out = new FileOutputStream( file );
		try {
			CommonHFSForkData fork = CommonHFSForkData.create( volumeHeaderFile );
			hfsxFileSystemView.extractForkToStream( fork, fork.getBasicExtents(), out, new NullProgressMonitor() {} );
		}
		finally {
			out.close();
		}
		return file;
	}
	
	public DecmpfsHeader getDecmpfsHeader(FSFile file) throws IOException {

		if ( root == null ) {
			return null;
		}

		if ( map.get( file ) != null ) {
			return map.get( file );
		}

		int fileID = getFileID( file );

		if ( fileID == -1 ) {
			return null;
		}

        for ( BTreeNodeDescriptor node : root.getNodes() ) {
			for ( BTreeNodeRecord record : node.getRecords() ) {
				if ( record.getFileID() == fileID ) {
					DecmpfsHeader header = record.getDecmpfsHeader();
					if ( header != null ) {
						map.put( file, header );
						return header;
					}
				}
			}
        }
        return null;
	}

	
}
