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

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Let Properties be Nested
 * by using ${}
 * */

public class PropertiesEnhance extends Properties {

    @Override
    public String getProperty(String key) {
        String str = super.getProperty(key);

        String pattern = "\\$\\{.*?}";
        Pattern r = Pattern.compile(pattern);
        Matcher m = r.matcher(str);

        while (m.find()) {
            String findKey = m.group();
            String fixKey = findKey.replaceAll("[${}]", "");
            String findValue = super.getProperty(fixKey);
            str = str.replaceAll(escapeExprSpecialWord(findKey), findValue);
        }
        return str;
    }

    /**
     * 转义正则特殊字符 （$()*+.[]?\^{},|）
     */
    public String escapeExprSpecialWord(String keyword) {
        if (keyword != null && keyword.length() > 0) {
            String[] fbsArr = { "\\", "$", "(", ")", "*", "+", ".", "[", "]", "?", "^", "{", "}", "|" };
            for (String key : fbsArr) {
                if (keyword.contains(key)) {
                    keyword = keyword.replace(key, "\\" + key);
                }
            }
        }
        return keyword;
    }
}

