/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.reader;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.InflaterInputStream;

import org.catacombae.dmgextractor.encodings.encrypted.ReadableCEncryptedEncodingStream;
import org.catacombae.hfsexplorer.FileSystemRecognizer;
import org.catacombae.hfsexplorer.PartitionSystemRecognizer;
import org.catacombae.hfsexplorer.UDIFRecognizer;
import org.catacombae.hfsexplorer.partitioning.Partition;
import org.catacombae.hfsexplorer.partitioning.PartitionSystem;
import org.catacombae.hfsexplorer.win32.WindowsLowLevelIO;
import org.catacombae.io.*;
import org.catacombae.jparted.lib.DataLocator;
import org.catacombae.jparted.lib.ReadableStreamDataLocator;
import org.catacombae.jparted.lib.fs.*;
import org.catacombae.jparted.lib.fs.FileSystemHandlerFactory.StandardAttribute;
import org.catacombae.jparted.lib.fs.hfsx.HFSXFileSystemHandler;
import org.catacombae.udif.UDIFFile;
import org.catacombae.udif.UDIFRandomAccessStream;

import mobiledevices.dmg.decmpfs.DecmpfsCompressionTypes;
import mobiledevices.dmg.decmpfs.DecmpfsHeader;
import mobiledevices.dmg.ghidra.*;
import mobiledevices.dmg.hfsplus.AttributesFileParser;

public class DmgFileReader implements Closeable {
	private final static GDataConverter ledc = new GDataConverterLE();
	private final static GDataConverter bedc = new GDataConverterBE();

	private GByteProvider provider;
	private AttributesFileParser parser;
	private ReadableRandomAccessStream rras;
	private List<FSFolder> rootFolders = new ArrayList<FSFolder>();
	private List<FileSystemHandler> fileSystemHandlers = new ArrayList<FileSystemHandler>();

	public DmgFileReader( GByteProvider provider ) {
		this.provider = provider;
	}

	public void open() throws IOException {

		File file = provider.getFile();

		if (WindowsLowLevelIO.isSystemSupported()) {
			rras = new WindowsLowLevelIO(file.getAbsolutePath());
		}
		else {
			rras = new ReadableFileStream(file.getAbsolutePath());
		}

		if (ReadableCEncryptedEncodingStream.isCEncryptedEncoding(rras)) {
			//TODO use our decryption instead??
		}

		System.err.println("Trying to detect UDIF structure...");
		if (UDIFRecognizer.isUDIF(rras)) {
			System.err.println("UDIF structure found! Creating filter stream...");

			UDIFFile udifFile = new UDIFFile(new ReadableFileStream(file.getAbsolutePath()));
			debug(udifFile.getView().getPlistData(), "dmg-xml");

			UDIFRandomAccessStream stream = new UDIFRandomAccessStream(rras);
			rras = stream;
		}
		else {
			System.err.println("UDIF structure not found. Proceeding...");
		}

		PartitionSystemRecognizer partitionSystemRecognizer = new PartitionSystemRecognizer(rras);
		PartitionSystem partitionSystem = partitionSystemRecognizer.getPartitionSystem();

		if (partitionSystem == null) {
			throw new IOException("No system partitions found. Perhaps the decryption failed?");
		}

		Partition[] partitions = partitionSystem.getUsedPartitionEntries();
		for (Partition partition : partitions) {
			openPartition(partition);
		}
	}

	private void debug( byte [] plistData, String fileName ) {
		// TODO Auto-generated method stub
	}

	private void openPartition( Partition selectedPartition ) throws IOException {
        long fsOffset = selectedPartition.getStartOffset();//getPmPyPartStart()+selectedPartition.getPmLgDataStart())*blockSize;
        long fsLength = selectedPartition.getLength();//getPmDataCnt()*blockSize;

        FileSystemRecognizer fsr = new FileSystemRecognizer( rras, fsOffset );
        FileSystemRecognizer.FileSystemType fsType = fsr.detectFileSystem();

        if ( fsType == FileSystemRecognizer.FileSystemType.HFS_PLUS ||
        	 fsType == FileSystemRecognizer.FileSystemType.HFSX ||
        	 fsType == FileSystemRecognizer.FileSystemType.HFS ) {

            final FileSystemMajorType fsMajorType;
            switch ( fsType ) {
                case HFS:
                    fsMajorType = FileSystemMajorType.APPLE_HFS;
                    break;
                case HFS_PLUS:
                    fsMajorType = FileSystemMajorType.APPLE_HFS_PLUS;
                    break;
                case HFSX:
                    fsMajorType = FileSystemMajorType.APPLE_HFSX;
                    break;
                default:
                    fsMajorType = null;
                    break;
            }

            FileSystemHandlerFactory factory = fsMajorType.createDefaultHandlerFactory();
            if ( factory.isSupported( StandardAttribute.CACHING_ENABLED ) ) {
                factory.getCreateAttributes().
                        setBooleanAttribute(StandardAttribute.CACHING_ENABLED,
                        true);
            }

            ReadableRandomAccessStream stage1;

            if (fsLength > 0) {
            	stage1 = new ReadableConcatenatedStream(rras, fsOffset, fsLength);
            }
            else {
            	stage1 = rras;
            }

            DataLocator dataLocator = new ReadableStreamDataLocator(stage1);

            FileSystemHandler fileSystemHandler = factory.createHandler(dataLocator);
            fileSystemHandlers.add( fileSystemHandler );

            rootFolders.add( fileSystemHandler.getRoot() );

            if ( fileSystemHandler instanceof HFSXFileSystemHandler ) {
            	parser = new AttributesFileParser( (HFSXFileSystemHandler)fileSystemHandler, fileSystemHandler.getRoot( ).getName( ) );
            }
        } else {
        		System.err.println("UNKNOWN file system type.  Can't Open filesystem.  Suspect this is an APFS.\n");
        }
	}

	@Override
	public void close() throws IOException {
		try {
			rras.close();
		}
		catch (Exception e) {
			//ignore
		}
		if ( parser != null ) {
			parser.dispose();
			parser = null;
		}
		fileSystemHandlers.clear();
		rootFolders.clear();
	}

	public InputStream getData( FSEntry entry ) throws IOException {
		if ( entry != null && entry.isFile() ) {
			FSFile fsFile = (FSFile)entry;
			FSFork mainFork = fsFile.getMainFork();
			if ( mainFork.getLength() > 0 ) {
				ReadableRandomAccessStream mainForkStream = mainFork.getReadableRandomAccessStream();
				if ( mainForkStream.length() != 0 ) {
					return new DmgInputStream( mainForkStream );
				}
			}
			else if ( mainFork.getLength() == 0 ) {

				FSFork resourceFork = fsFile.getForkByType( FSForkType.MACOS_RESOURCE );
				ReadableRandomAccessStream resourceForkStream = resourceFork.getReadableRandomAccessStream();

				if ( parser == null ) {
					return null;
				}

				DecmpfsHeader decmpfsHeader = parser.getDecmpfsHeader( fsFile );

				if ( decmpfsHeader == null ) {
					return null;
				}

				if ( decmpfsHeader.getCompressionType() == DecmpfsCompressionTypes.CMP_Type3 ) {

					if ( decmpfsHeader.getAttrBytes()[ 0 ] == -1 ) {
						return new ByteArrayInputStream(decmpfsHeader.getAttrBytes(), 1,
							decmpfsHeader.getAttrBytes().length - 1);
					}

					return new RestrictedInflaterInputStream(decmpfsHeader.getAttrBytes(),
						(int) decmpfsHeader.getUncompressedSize());
				}
				else if ( decmpfsHeader.getCompressionType() == DecmpfsCompressionTypes.CMP_Type4 ) {
					return decompressResourceFork(entry, resourceForkStream,
						(int) decmpfsHeader.getUncompressedSize());
				}
			}
		}
		return null;
	}

	private InputStream decompressResourceFork( FSEntry entry, 
												ReadableRandomAccessStream resourceForkStream,
												int expectedLength ) throws IOException {

		File tempFile = GFileUtilityMethods.writeTemporaryFile( new DmgInputStream( resourceForkStream ) );
		System.err.println(
			"dmg resource fork for " + entry.getName() + ": " + tempFile.getAbsolutePath());

		// Copy compressed portion of tempFile to tempCompressedFile
		File tempCompressedFile;
		try (InputStream input = new FileInputStream(tempFile)) {

			for (int i = 0; i < 0x100; ++i) {
				input.read();
			}

			byte[] sizeBytes = new byte[4];
			input.read(sizeBytes);
			int size = sizeBytes[0] == 0 ? bedc.getInt(sizeBytes) : ledc.getInt(sizeBytes);

			byte[] flagsBytes = new byte[4];
			input.read(flagsBytes);

			byte[] startDistanceBytes = new byte[4];
			input.read(startDistanceBytes);
			int startDistance = ledc.getInt(startDistanceBytes);

			input.skip(startDistance - 8);//skip to the start of the zlib compressed file

			tempCompressedFile =
				GFileUtilityMethods.writeTemporaryFile(input, size - startDistance);
		}
		finally {
			tempFile.delete();
		}

		return new RestrictedInflaterInputStream(tempCompressedFile, expectedLength);
	}

	private class RestrictedInflaterInputStream extends InflaterInputStream {

		private File tempCompressedFile;
		private int readLimit;
		private int readCount = 0;

		/**
		 * Creates a new Inflater input stream with a default decompressor and buffer size.
		 * NOTE: The default Inflater instance will be ended when this stream closes.
		 * @param tempCompressedFile the temporary file containing compressed data.  File will be
		 * removed when this stream is closed.
		 * @param readLimit maximum data read count.  Exceeding this limit will result in an
		 * IOException.
		 * @throws FileNotFoundException if tempCompressedFile does not exist
		 */
		RestrictedInflaterInputStream(File tempCompressedFile, int readLimit)
				throws FileNotFoundException {
			super(new FileInputStream(tempCompressedFile));
			this.tempCompressedFile = tempCompressedFile;
			this.readLimit = readLimit;
		}

		/**
		 * Creates a new Inflater input stream with a default decompressor and buffer size.
		 * NOTE: The default Inflater instance will be ended when this stream closes.
		 * @param compressedData the byte array containing compressed data.
		 * @param readLimit maximum data read count.  Exceeding this limit will result in an
		 * IOException.
		 */
		RestrictedInflaterInputStream(byte[] compressedData, int readLimit) {
			super(new ByteArrayInputStream(compressedData));
			this.tempCompressedFile = null;
			this.readLimit = readLimit;
		}

		@Override
		public void close() throws IOException {
			try {
				super.close();
			}
			finally {
				// Cleanup temporary file input stream and remove file
				in.close();
				if (tempCompressedFile != null) {
					tempCompressedFile.delete();
				}
			}
		}

		@Override
		public int read(byte[] b, int off, int length) throws IOException {
			if (length == 0) {
				return 0;
			}
			if (readCount >= readLimit) {
				throw new IOException("Decompression limit exceeded: " + readLimit);
			}
			// Limit read length to avoid exceeding readLimit
			int limit = Math.min(readLimit - readCount, length);
			int count = super.read(b, off, limit);
			if (count > 0) {
				readCount += count;
			}
			return count;
		}
	}

	public List<String> getInfo( String path ) {
		if ( path != null ) {
			DmgInfoGenerator info = new DmgInfoGenerator( this, path, parser );
			return info.getInformation( );
		}
		return null;
	}

	public List<FSEntry> getListing( String path ) {
		List<FSEntry> list = new ArrayList<FSEntry>();
		if ( path == null || path.equals( "/" ) ) {
			for ( FileSystemHandler handler : fileSystemHandlers ) {
				list.add( handler.getRoot() );
			}
		}
		else {
			FSEntry fileByPath = getFileByPath( path );
			if ( fileByPath != null ) {
				if ( fileByPath.isFolder() ) {
					FSEntry [] listEntries = fileByPath.asFolder().listEntries();
					for ( FSEntry entry : listEntries ) {
						list.add( entry );
					}
				}
			}
		}
		return list;
	}

	/**
	 * Returns the length of the given file system entry.
	 * If the entry is actually a directory, then -1 is returned.
	 */
	public long getLength( FSEntry entry ) {
		if (entry != null && entry.isFile()) {
			FSFork mainFork = entry.asFile().getMainFork();
			if ( mainFork.getLength() > 0 ) {
				return mainFork.getLength();
			}
			try {
				if (parser != null) {
					DecmpfsHeader header = parser.getDecmpfsHeader(entry.asFile());
					if (header != null) {
						return header.getUncompressedSize();
					}
				}
			}
			catch (IOException e) {
				return 1;//TODO lookup valid length in DECMPFS
			}
		}
		return -1;
	}

	/**
	 * Convert path to string array.
	 * 
	 * For example, "/a/b/c.txt" will be converted to [ "a", "b", "c.txt" ].
	 * 
	 * Note: the "a" will be stripped because it corresponds to the file system handler.
	 */
	public String [] convertPathToArrayAndStripFileSystemName( String path ) {
		String [] splitPath = path.split( "/" );
		if ( splitPath.length <= 2 ) {
			return new String[ 0 ];
		}
		String [] temp = new String[ splitPath.length - 2 ];
		System.arraycopy( splitPath, 2, temp, 0, splitPath.length - 2 );
		return temp;
	}

	/**
	 * Returns the DMG file object for the corresponding path.
	 * Path should contain the file system handler name.
	 */
	public FSEntry getFileByPath( String path ) {
		if ( path == null || path.equals( "/" ) ) {//ROOT
			return null;
		}
		for ( FileSystemHandler handler : fileSystemHandlers ) {
			FSEntry entry = handler.getEntry( convertPathToArrayAndStripFileSystemName( path ) );
			if ( entry != null ) {
				return entry;
			}
		}
		return null;
	}

}
