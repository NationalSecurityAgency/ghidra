/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.server;

import java.io.*;
import java.util.List;

import org.catacombae.jparted.lib.fs.*;

import mobiledevices.dmg.ghidra.GByteProvider;
import mobiledevices.dmg.ghidra.GFileUtilityMethods;
import mobiledevices.dmg.reader.DmgFileReader;

public class DmgServer {

	private static void writeln(String s) {

		StringBuilder encoded = new StringBuilder();
		char[] charArray = s.toCharArray();
		for (char c : charArray) {
			if (c == 11) {
				encoded.append(c);// tab
			}

			if (c <= 31 || c == 127) {
				continue;// control characters
			}

			encoded.append(c);
		}

		System.out.println(encoded.toString());
	}

	public static void sendResponse(String s) {
		System.out.println(s);
		System.out.flush();
	}

	public static void sendResponses(String... responseStrs) {
		for (String s : responseStrs) {
			System.out.println(s);
		}
		System.out.flush();
	}

	public static void log(String... logstrs) {
		for (String s : logstrs) {
			System.err.println(s);
		}
		System.err.flush();
	}

	public static void main(String[] args) {

		log("Waiting for client to connect to DMG server...");

		BufferedReader inputReader = new BufferedReader(new InputStreamReader(System.in));

		try {
			String openLine = inputReader.readLine();
			if (openLine == null) {
				return;
			}
			if (!openLine.startsWith("open ")) {
				return;//TODO handle invalid initial command???
			}
			String openPath = parseLine(openLine);

			File openFile = new File(openPath);
			if (!openFile.exists()) {//TODO handle files that do not exist

			}

			try (GByteProvider provider = new GByteProvider(openFile);
					DmgFileReader dmgFileReader = new DmgFileReader(provider);) {
				dmgFileReader.open();
				while (true) {
					String line = inputReader.readLine();
					if (line == null) {
						break;
					}
					String[] parts = line.split(" ", 2);
					if (parts.length < 1)
						continue;
					String cmd = parts[0];
					switch (cmd) {
						case "close":
							log("Exiting DMG server process: close cmd");
							return;
						case "get_listing": {
							String path = parseLine(line);
							List<FSEntry> listing = dmgFileReader.getListing(path);
							sendResponse("" + listing.size());//write total number of children
							for (FSEntry childEntry : listing) {
								// send 3 responses: name, isfolder boolean, file length
								writeln(childEntry.getName());//write name of each child
								sendResponses("" + childEntry.isFolder(),
									"" + dmgFileReader.getLength(childEntry));
							}
						}
							break;
						case "get_info": {
							String path = parseLine(line);
							List<String> infoList = dmgFileReader.getInfo(path);
							sendResponse("" + infoList.size());//write total number of info lines
							for (String info : infoList) {
								sendResponse(info);//write each info line
							}
						}
							break;
						case "get_data": {
							String path = parseLine(line);

							FSFile dmgFile = toFile(dmgFileReader, path);

							if (dmgFile == null) {//TODO not a valid file...
								sendResponse("");
							}
							else {
								long expectedFileLength = dmgFileReader.getLength(dmgFile);

								try (InputStream inputStream = dmgFileReader.getData(dmgFile)) {
									if (inputStream != null) {
										File temporaryFile =
											GFileUtilityMethods.writeTemporaryFile(inputStream);

										sendResponse(temporaryFile.getAbsolutePath());

										if (expectedFileLength != temporaryFile.length()) {
											log("file sizes do not match!");
										}
									}
									else {
										sendResponse("");// TODO: is this correct way to respond when error cond?
										log("No data stream for get_data for " + path);
									}
								}
							}
						}
							break;
					}
				}
			}
		}
		catch (IOException e) {
			log("IOException error in DMGServer command processing: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		finally {
			log("DMG server has terminated.");
		}
	}

	private static FSFile toFile(DmgFileReader dmgFileReader, String path) {
		FSEntry entry = dmgFileReader.getFileByPath(path);

		if (entry == null) {
			//System.err.println("Bad path for toFile: " + path);
			return null;
		}
		if (entry.isFile()) {
			return entry.asFile();
		}
		else if (entry instanceof FSLink) {
			int limit = 0;
			while (limit++ < 10) {
				FSLink link = (FSLink) entry;

				FSEntry linkTarget = link.getLinkTarget(
					dmgFileReader.convertPathToArrayAndStripFileSystemName(path));

				if (linkTarget instanceof FSFile) {
					return linkTarget.asFile();
				}
				else if (linkTarget instanceof FSLink) {
					entry = linkTarget;
				}
				else {//anything else just return
					break;
				}
			}
		}
		return null;
	}

	private static String parseLine(String openLine) {
		int space = openLine.indexOf(' ');
		String path = openLine.substring(space + 1).trim();
		return path;
	}
}
