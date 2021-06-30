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

import resources.ResourceManager;

import java.awt.*;
import java.io.InputStream;


import static ghidra.util.config.ColorHexConvert.toColorFromString;
import static ghidra.util.config.PropertiesHandle.GetValueByKey;

/**
 * Get Color from Config file
 * */
public class ReadColorFromConfig {

    public static Color findColor(String key){
        return ReadColorFromProperties(key);
    }

    /**
     * ReadColorFromProperties
     * @param key String
     * @return Color Object
     * */
    private static Color ReadColorFromProperties(String key) {

//        String ColorConfigFile = "Ghidra/Framework/Docking/src/main/resources/config/Color.properties";
        InputStream ColorConfigFile = ResourceManager.getResourceAsStream("config/Color.properties");
        Color color = toColorFromString(GetValueByKey(ColorConfigFile, key));
        return color;
    }
}
