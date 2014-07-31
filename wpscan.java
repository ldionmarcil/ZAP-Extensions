/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.ascanrules;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Random;
import org.parosproxy.paros.Constant;

import java.util.Map;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URLDecoder;

import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.AbstractAppPlugin;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

import org.apache.commons.httpclient.URI;
import java.io.IOException;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import difflib.Delta;
import difflib.DiffUtils;
import difflib.Patch;

public class wpscan extends AbstractHostPlugin
{
    private static Logger log = Logger.getLogger(wpscan.class);

    @Override
    public void init() {
    }

    @Override
    public void scan() {
        try {
            URI originalURI = this.getBaseMsg().getRequestHeader().getURI();
            String target = originalURI.getScheme() + "://" +originalURI.getAuthority();
            log.info("Starting wpscan... Target is " + target);
            log.info(target);
            ProcessBuilder builder = new ProcessBuilder("/usr/bin/wpscan", "--url", target);
            builder.redirectErrorStream(true);
            Process process = builder.start();

            BufferedReader reader = new BufferedReader (new InputStreamReader(process.getInputStream()));

	    String fileExistsPatternString = "^\\[31m\\[!\\]\\[0m The WordPress '(.*)' file exists$";
	    Pattern fileExistsPattern = Pattern.compile(fileExistsPatternString, Pattern.MULTILINE);

	    String backupExistsPatternString = "^\\[31m\\[!\\]\\[0m A (.*) backup file has been found in: '(.*)'$";
	    Pattern backupExistsPattern = Pattern.compile(backupExistsPatternString, Pattern.MULTILINE);

	    String vulnWithReferencePatternString = "^\\[31m\\[!\\]\\[0m(?:Title:)? (.*)\n    Reference: (.*)";
	    Pattern vulnWithReferencePattern = Pattern.compile(vulnWithReferencePatternString, Pattern.MULTILINE);

	    String vulnPatternString = "^\\[31m\\[!\\]\\[0m(?: Title\\:)? (.*)";
	    Pattern vulnPattern = Pattern.compile(vulnPatternString);

	    String blockDelimiterPatternString = ".*\n\n.*";
	    Pattern blockDelimiterPattern = Pattern.compile(blockDelimiterPatternString, Pattern.MULTILINE);

	    String line;
	    String buffer = "";
	    while ((line = reader.readLine()) != null) {
		buffer += line+"\n";
	
		Matcher blockDelimiterMatcher = blockDelimiterPattern.matcher(buffer);

		if (blockDelimiterMatcher.find()) { // new block, process it.
		    Matcher fileExistsMatcher = fileExistsPattern.matcher(buffer);
		    Matcher backupExistsMatcher = backupExistsPattern.matcher(buffer);
		    Matcher vulnWithReferenceMatcher = vulnWithReferencePattern.matcher(buffer);
		    Matcher vulnMatcher = vulnPattern.matcher(buffer);

		    while (fileExistsMatcher.find()) {
			bingo(Alert.RISK_INFO, Alert.WARNING, "WordPress installation file", "A WordPress installation is present on the server.", fileExistsMatcher.group(1), "", fileExistsMatcher.group(1), "", "These files should be removed from the server upon installation.", "Remove installation files.", getNewMsg());
		    }
		    while (backupExistsMatcher.find()) {
			bingo(Alert.RISK_HIGH, Alert.WARNING, "WordPress "+backupExistsMatcher.group(1)+" backup file", "A WordPress configuration back file is present on the server.", backupExistsMatcher.group(2), "", backupExistsMatcher.group(2), "", "Backup files should not be accessible from the web server.", "Backup your files at a safe place that is not acessible from the web server.", getNewMsg());
		    } 
		    if (vulnWithReferenceMatcher.find()) {
			bingo(Alert.RISK_HIGH, Alert.WARNING, vulnWithReferenceMatcher.group(1), "Wordpress Vulnerability.", vulnWithReferenceMatcher.group(1), "", vulnWithReferenceMatcher.group(1), vulnWithReferenceMatcher.group(2), "", ".", getNewMsg());
		    } else if (vulnMatcher.find()) {
			bingo(Alert.RISK_HIGH, Alert.WARNING, vulnMatcher.group(1), "Wordpress Vulnerability.", vulnMatcher.group(1), "", vulnMatcher.group(1), "", "", ".", getNewMsg());
		    }

		    buffer = ""; //clear buffer
		} 
	    }

        } catch (Exception e) {
            log.info("Error" + e.getMessage());
        }
    }


    @Override
    public int getId() {
        return 33003;
    }

    @Override
    public String getName() {
        return "wpscan";
    }

    @Override
    public int getCategory()
    {
        return Category.INFO_GATHER;
    }
    @Override
    public String[] getDependency()
    {
        return null;
    }

    @Override
    public String getDescription()
    {
        return "Word press passive scanner";
    }

    @Override
    public String getSolution()
    {
        return "Update WordPress.";
    }

    @Override
    public String getReference()
    {
        return "Failed to load vulnerability reference from file";
    }

    @Override
    public int getRisk() {
        return Alert.RISK_HIGH;
    }
}
