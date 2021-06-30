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

package ghidra.util.config;

import java.io.*;
import java.util.Enumeration;

public class PropertiesHandle {

    /**
     * Find the value according to Key
     * @param filePath Filepath String
     * @param key String
     * @return Value String
     * */
    public static String GetValueByKey(String filePath, String key) {
        PropertiesEnhance pps = new PropertiesEnhance();
        try {
            InputStream in = new BufferedInputStream(new FileInputStream(filePath));
            pps.load(in);
            String value = pps.getProperty(key);
            return value;

        }catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String GetValueByKey(InputStream fileStream, String key) {
        PropertiesEnhance pps = new PropertiesEnhance();
        try {
            InputStream in = fileStream;
            pps.load(in);
            String value = pps.getProperty(key);
            return value;

        }catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * Read all value from properties file
     * @param filePath Filepath String
     * @return Value String
     * */
    public static void GetAllProperties(String filePath) throws IOException {
        PropertiesEnhance pps = new PropertiesEnhance();
        InputStream in = new BufferedInputStream(new FileInputStream(filePath));
        pps.load(in);
        Enumeration en = pps.propertyNames();
        while(en.hasMoreElements()) {
            String strKey = (String) en.nextElement();
            String strValue = pps.getProperty(strKey);
        }

    }

    /**
     * Write value to properties file
     * @param filePath Filepath String
     * @param pKey String
     * @param pValue Sting
     * */
    public static void WriteProperties (String filePath, String pKey, String pValue) throws IOException {
        PropertiesEnhance pps = new PropertiesEnhance();
        InputStream in = new FileInputStream(filePath);
        pps.load(in);
        OutputStream out = new FileOutputStream(filePath);
        pps.setProperty(pKey, pValue);
        pps.store(out, "Update " + pKey + " name");
    }
}
