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
package ghidra.app.plugin.core.go.ipc;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.URL;
import java.nio.channels.FileLockInterruptionException;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.*;
import java.util.function.Consumer;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.core.go.exception.UnableToGetLockException;
import ghidra.framework.main.AppInfo;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class GhidraGoListener extends GhidraGoIPC implements Runnable {
	public static int WAIT_FOR_ACTIVE_PROJECT_TIMEOUT_S = 30;

	private Thread t;
	private Consumer<URL> onNewUrl;

	/**
	 * Begin listening for urls in a non-blocking thread. If a listener already exists, the thread 
	 * will wait until no listener exists and attempt to get the lock. Once the lock has been acquired
	 * the listener will start watching for new urls and create a ready lock. Upon a new url being found,
	 * the onNewUrl Consumer will be executed.
	 * @param onNewUrl consumer method to execute upon finding a new url
	 * @throws IOException if the Runnable cannot be created
	 */
	public GhidraGoListener(Consumer<URL> onNewUrl) throws IOException {
		super();
		this.onNewUrl = onNewUrl;
		t = new Thread(this, "GhidraGo Handler");
		t.start();
	}

	@Override
	public void run() {
		try {
			doLockedAction(listenerLockPath, true, () -> {
				try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
					urlFilesPath.register(watchService, StandardWatchEventKinds.ENTRY_CREATE);
					Msg.info(this, "Listening for GhidraGo Requests.");
					doLockedAction(listenerReadyLockPath, true, () -> {
						try {
							WatchKey key;
							while ((key = watchService.take()) != null) {
								for (WatchEvent<?> event : key.pollEvents()) {
									// only process events that are not null. null events could happen 
									// when event.kind() is OVERFLOW.
									if (event.context() != null) {
										Msg.trace(this, event.context() + " is a new file!");
										// get the url from the new url
										Path urlFilePath =
											urlFilesPath.resolve(event.context().toString());
										URL url = getGhidraURL(urlFilePath);
										urlFilePath.toFile().delete();
										if (url != null) {
											onNewUrl.accept(url);
										}
									}
								}
								key.reset();
							}
						}
						catch (InterruptedException e) {
							// watch service interrupted
						}
						return true;
					});
				}
				catch (FileLockInterruptionException | InterruptedIOException e) {
					return false;
				}
				catch (IOException | UnableToGetLockException e) {
					Swing.runNow(() -> Msg.showError(this, null,
						"GhidraGo Unable to Watch for New GhidraURL's", e));
					return false;
				}
				catch (ClosedWatchServiceException e) {
					// do nothing
				}
				finally {
					Msg.info(this, "No longer listening for GhidraGo Requests.");
				}
				return true;
			});
		}
		catch (OverlappingFileLockException | UnableToGetLockException e) {
			Swing.runNow(
				() -> Msg.showError(this, null, "GhidraGo Unable to Watch for New GhidraURL's", e));
		}
	}

	/**
	 * Returns a URL given the first argument from GhidraGo.
	 * @param ghidraGoArgument could be a GhidraURL or a projectFilePath.
	 * @return the GhidraURL to a program
	 * @throws IllegalArgumentException in the event the given GhidraGo argument is invalid
	 */
	private URL toURL(String ghidraGoArgument) throws IllegalArgumentException {
		try {

			if (ghidraGoArgument.startsWith(GhidraURL.PROTOCOL + ":?")) {
				String projectFilePath =
					ghidraGoArgument.substring(ghidraGoArgument.indexOf("?") + 1);
				if (!projectFilePath.startsWith("/")) {
					projectFilePath = "/" + projectFilePath;
				}
				return GhidraURL.makeURL(AppInfo.getActiveProject().getProjectLocator(),
					projectFilePath, null);
			}
			return GhidraURL.toURL(ghidraGoArgument);

		}
		catch (IllegalArgumentException e) {
			if (ghidraGoArgument.startsWith(GhidraURL.PROTOCOL + "://") ||
				AppInfo.getActiveProject() == null)
				throw e;
			if (!ghidraGoArgument.startsWith("/")) {
				ghidraGoArgument = "/" + ghidraGoArgument;
			}
			return GhidraURL.makeURL(AppInfo.getActiveProject().getProjectLocator(),
				ghidraGoArgument, null);
		}
	}

	/**
	 * Reads the url file for the url string and returns it.
	 * @param urlFilePath the path for the url file
	 * @return the url string, or null if the file cannot be read.
	 */
	private URL getGhidraURL(Path urlFilePath) {
		try {
			String urlContents = new String(Files.readAllBytes(urlFilePath));
			if (StringUtils.isEmpty(urlContents)) {
				Swing.runNow(() -> Msg.showError(GhidraGoIPC.class, null,
					"GhidraGo Empty GhidraURL Read",
					"The GhidraURL read from url file was null or empty. This should not happen, " +
						"ensure ghidraGo is being used properly."));
				return null;
			}

			return toURL(urlContents);
		}
		catch (IOException e) {
			Swing.runNow(() -> Msg.showError(GhidraGoIPC.class, null, "GhidraGo Error",
				"Failed to read the url from " + urlFilePath, e));
		}
		catch (IllegalArgumentException e) {
			Swing.runNow(
				() -> Msg.showError(GhidraGoIPC.class, null, "GhidraGo Illegal Argument Given", e));
		}
		return null;
	}

	@Override
	public void dispose() {
		if (t != null) {
			t.interrupt();
		}
	}

}
