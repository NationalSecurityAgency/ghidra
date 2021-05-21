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
package ghidra.net.http;

import java.io.*;
import java.net.*;
import java.util.Properties;

import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.util.Msg;

public class HttpUtil {


	/**
	 * Execute an HTTP/HTTPS GET request and return the resulting HttpURLConnection.
	 * @param httpUrlString HTTP/HTTPS URL
	 * @param httpRequestProperties optional HTTP request header values to be included (may be null)
	 * @param allowRedirect allow site redirects to be handled if true
	 * @return HttpURLConnection which contains information about the URL
	 * @throws MalformedURLException bad httpUrlString specified
	 * @throws IOException if an error occurs while executing request
	 */
	public static HttpURLConnection getContent(String httpUrlString,
			Properties httpRequestProperties, boolean allowRedirect) throws MalformedURLException,
			IOException {

		URL url = new URL(httpUrlString);
		String protocol = url.getProtocol();

		if ("https".equals(protocol)) {
			// force password prompt before connecting
			if (!ApplicationKeyManagerFactory.initialize()) {
				if (ApplicationKeyManagerFactory.getKeyStore() != null) {
					// Report error condition?
					throw new IOException("Failed to initialize PKI certificate keystore");
				}
				// continue without private keystore
			}
		}
		else if (!"http".equals(protocol)) {
			throw new MalformedURLException("Unsupported protocol: " + protocol);
		}

		HttpURLConnection c = (HttpURLConnection) url.openConnection();
		if (allowRedirect) {
			c.setInstanceFollowRedirects(true);
		}
		c.setRequestMethod("GET");
		if (httpRequestProperties != null) {
			for (String name : httpRequestProperties.stringPropertyNames()) {
				c.setRequestProperty(name, httpRequestProperties.getProperty(name));
			}
		}

		int rc = c.getResponseCode();
		if (rc != HttpURLConnection.HTTP_OK) {
			throw new IOException(c.getResponseMessage());
		}

		Msg.info(HttpUtil.class, "Get URL content: " + url);
		if (!url.equals(c.getURL())) {
			Msg.info(HttpUtil.class, "Actual URL: " + c.getURL());
		}
		Msg.info(HttpUtil.class, " > Content-Type=" + c.getHeaderField("Content-Type"));

		String contentLengthStr = c.getHeaderField("Content-Length");
		if (contentLengthStr == null) {
			c.disconnect();
			String encodingStr = c.getHeaderField("Transfer-Encoding");
			if (encodingStr != null) {
				throw new IOException("Unsupport HTTP transfer encoding: " + encodingStr);
			}
			throw new IOException("Unsupported HTTP transfer (Content-Length not specified)");
		}
		Msg.info(HttpUtil.class, " > Content-Length=" + contentLengthStr);

		return c;
	}

	/**
	 * Download a file by executing an HTTP/HTTPS GET request.
	 * @param httpUrlString HTTP/HTTPS URL
	 * @param httpRequestProperties optional HTTP request header values to be included (may be null)
	 * @param allowRedirect allow site redirects to be handled if true
	 * @param destFile destination file
	 * @throws MalformedURLException bad httpUrlString specified
	 * @throws IOException if an error occurs while executing request
	 * @return String representing the content-type of the file, or null if the information is not available
	 */
	public static String getFile(String httpUrlString, Properties httpRequestProperties,
			boolean allowRedirect, File destFile) throws MalformedURLException, IOException {

		HttpURLConnection connection = null;
		InputStream content = null;
		try {

			connection = getContent(httpUrlString, httpRequestProperties, allowRedirect);
			content = connection.getInputStream();

			BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(destFile));
			byte[] dataBuffer = new byte[8 * 1024];
			try {
				int len;
				while ((len = content.read(dataBuffer)) >= 0) {
					out.write(dataBuffer, 0, len);
				}
			}
			finally {
				out.close();
			}
		}
		finally {
			if (content != null) {
				content.close();
			}
		}

		return connection.getContentType();
	}

}
