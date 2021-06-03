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
package ghidra.util;

import java.net.MalformedURLException;
import java.net.URL;

import resources.ResourceManager;

/**
 * Class to identify where help can be located for some object. Help can be
 * set on actions or dialogs.
 */
public class HelpLocation {

	private String id;
	private URL url;

	private String topic;
	private String anchor;

	private String inceptionInformation;

	/**
	 * Flag for lazy-loading the URL value of this class
	 */
	private boolean urlInitialized;

	/**
	 * Construct a Help location using the specified topic and anchor names.
	 * An html file contained within the specified help topic directory must have an Anchor
	 * defined using the specified anchor name.
	 * <p>
	 * <b>Note:</b>  You can specify a <code>null</code> anchor value.  In that case, the given topic
	 * will be searched for a file with the same name as the topic.  If such a file exists, 
	 * then that file will be used as the file for this location.  If no such file exists, then 
	 * the help file to use <b>cannot be resolved</b>.  Therefore, it is best to always specify
	 * a value for the help location.
	 *    
	 * @param topic topic directory name
	 * @param anchor anchor name or null
	 */
	public HelpLocation(String topic, String anchor) {
		this(topic, anchor, createInception());
	}

	/**
	 * Construct a Help location using the specified topic and anchor names.
	 * An html file contained within the specified help topic directory must have an Anchor
	 * defined using the specified anchor name.
	 * <p>
	 * <b>Note:</b>  You can specify a <code>null</code> anchor value.  In that case, the given topic
	 * will be searched for a file with the same name as the topic.  If such a file exists, 
	 * then that file will be used as the file for this location.  If no such file exists, then 
	 * the help file to use <b>cannot be resolved</b>.  Therefore, it is best to always specify
	 * a value for the help location.
	 *    
	 * @param topic topic directory name
	 * @param anchor anchor name or null
	 * @param inceptionInformation the description of from whence the item 
	 *        described by this location has come; can be null
	 *        
	 */
	public HelpLocation(String topic, String anchor, String inceptionInformation) {
		if (topic == null) {
			topic = "UnknownTopic";
		}

		anchor = fixString(anchor, false);
		this.topic = topic;
		this.anchor = anchor;
		id = buildId(topic, anchor);

		this.inceptionInformation = inceptionInformation;
	}

	private URL getURL() {
		if (!urlInitialized) {
			urlInitialized = true;
			url = buildURL(topic, anchor);
		}

		return url;
	}

	private static String fixString(String str, boolean allowFilePath) {
		if (str == null) {
			return str;
		}
		StringBuffer buf = new StringBuffer(str);
		int n = buf.length();
		for (int i = 0; i < n; i++) {
			char c = buf.charAt(i);
			if (allowFilePath && (c == '.' || c == '/')) {
				continue;
			}
			if (!Character.isLetterOrDigit(c)) {
				buf.setCharAt(i, '_');
			}
		}
		return buf.toString();
	}

	private String buildId(String localTopic, String localAnchor) {
		if (localTopic.indexOf(".htm") >= 0) {
			return null;
		}
		if (localAnchor == null) {
			return localTopic;
		}
		int ix = localAnchor.indexOf(".htm");
		if (ix >= 0) {
			localAnchor = localAnchor.substring(0, ix);
		}
		localTopic = fixString(localTopic, false);
		return localTopic + "_" + localAnchor;
	}

	private URL buildURL(String localTopic, String localAnchor) {

		String topicPath = fixString(localTopic, true);
		URL localURL = findHelpResource(topicPath);

		// try creating a URL with the given anchor
		if (localURL != null && localAnchor != null) {
			try {
				localURL = new URL(localURL.toExternalForm() + "#" + localAnchor);
			}
			catch (MalformedURLException e) {
				// we tried
			}
		}
		return localURL;
	}

	private URL findHelpResource(String topicPath) {
		if (topicPath.indexOf(".htm") >= 0) {
			return ResourceManager.getResource("/help/topics/" + topicPath);
		}

		String filename = topicPath + ".htm";
		URL fileURL = ResourceManager.getResource("/help/topics/" + filename);
		if (fileURL != null) {
			return fileURL;
		}

		filename = topicPath + ".html";
		fileURL = ResourceManager.getResource("/help/topics/" + filename);
		if (fileURL != null) {
			return fileURL;
		}
		return null;
	}

	/**
	 * Get the help ID for this help location.
	 * @return null if there is a Help URL instead of a help ID
	 */
	public String getHelpId() {
		return id;
	}

	/**
	 * Returns the topic name/path if known, otherwise null.
	 */
	public String getTopic() {
		return topic;
	}

	/**
	 * Returns the topic anchor name if known, otherwise null.
	 */
	public String getAnchor() {
		return anchor;
	}

	/**
	 * Get the help URL for this help location. A URL is created when the
	 * constructor <code>HelpLocation(Class, String, String)</code> is
	 * used by a plugin that has help relative to its class.
	 * @return the URL or null if a help ID is used
	 */
	public URL getHelpURL() {
		return getURL();
	}

	@Override
	public String toString() {
		URL helpURL = getURL();
		if (helpURL != null) {
			return helpURL.toString();
		}
		if (id != null) {
			return id;
		}
		return "<Unknown>";
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((anchor == null) ? 0 : anchor.hashCode());
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		result = prime * result + ((topic == null) ? 0 : topic.hashCode());

		URL helpURL = getURL();
		result = prime * result + ((helpURL == null) ? 0 : helpURL.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		HelpLocation other = (HelpLocation) obj;
		if (anchor == null) {
			if (other.anchor != null) {
				return false;
			}
		}
		else if (!anchor.equals(other.anchor)) {
			return false;
		}
		if (id == null) {
			if (other.id != null) {
				return false;
			}
		}
		else if (!id.equals(other.id)) {
			return false;
		}
		if (topic == null) {
			if (other.topic != null) {
				return false;
			}
		}
		else if (!topic.equals(other.topic)) {
			return false;
		}

		URL helpURL = getURL();
		if (helpURL == null) {
			if (other.getURL() != null) {
				return false;
			}
		}
		else if (!helpURL.equals(other.getURL())) {
			return false;
		}
		return true;
	}

	/**
	 * Returns information describing how/where this help location was created.  This value may
	 * be null.
	 * @return information describing how/where this help location was created.
	 */
	public String getInceptionInformation() {
		return inceptionInformation;
	}

//==================================================================================================
// Utility Methods
//==================================================================================================

	private static String createInception() {
		if (!SystemUtilities.isInDevelopmentMode()) {
			return null;
		}

		Throwable throwable = new Throwable();
		StackTraceElement[] stackTrace = throwable.getStackTrace();

		String information = getInceptionInformationFromTheFirstClassThatIsNotUs(stackTrace);
		return information;
	}

	private static String getInceptionInformationFromTheFirstClassThatIsNotUs(
			StackTraceElement[] stackTrace) {

		// To find our creation point we can use a simple algorithm: find the name of our class, 
		// which is in the first stack trace element and then keep walking backwards until that
		// name is not ours.
		//         
		String myClassName = HelpLocation.class.getName();
		int myClassNameStartIndex = -1;
		for (int i = 1; i < stackTrace.length; i++) { // start at 1, because we are the first item
			StackTraceElement stackTraceElement = stackTrace[i];
			String elementClassName = stackTraceElement.getClassName();
			if (myClassName.equals(elementClassName)) {
				myClassNameStartIndex = i;
				break;
			}
		}

		int creatorIndex = myClassNameStartIndex;
		for (int i = myClassNameStartIndex; i < stackTrace.length; i++) { // start at 1, because we are the first item
			StackTraceElement stackTraceElement = stackTrace[i];
			String elementClassName = stackTraceElement.getClassName();

			if (!myClassName.equals(elementClassName)) {
				creatorIndex = i;
				break;
			}
		}

		return stackTrace[creatorIndex].toString();
	}
}
