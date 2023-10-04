/*
 * This file is part of CycloneDX Maven Plugin.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.cyclonedx.maven;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;

import com.jayway.jsonpath.JsonPath;

import io.takari.maven.testing.executor.MavenRuntime.MavenRuntimeBuilder;
import io.takari.maven.testing.executor.MavenVersions;
import io.takari.maven.testing.executor.junit.MavenJUnitTestRunner;
import net.minidev.json.JSONArray;

/**
 * Test for https://github.com/CycloneDX/cyclonedx-maven-plugin/issues/389.
 * Extraction of copyright information from license and notice files.
 */
@RunWith(MavenJUnitTestRunner.class)
@MavenVersions({"3.6.3"})
public class CopyrightDetectionTest extends BaseMavenVerifier {
	private static final Map<String, String> EXPECTED_COPYRIGHTS = new HashMap<>();
	
	static {
		// text block and single line in NOTICE
		EXPECTED_COPYRIGHTS.put("jackson-core",
				"2023 Werner Randelshofer, Switzerland.; 2020 Tim Buktu; 2007-, Tatu Saloranta (tatu.saloranta@iki.fi); 2022 Daniel Lemire; 2022 Tim Buktu; 2023 Werner Randelshofer, Switzerland; 2021 The fast_float authors");
		// Several copyrights in LICENSE
		EXPECTED_COPYRIGHTS.put("icu4j",
				"1995-2016 International Business Machines Corporation and others; 1991-2023 Unicode, Inc. All rights reserved.; 2006-2011, the V8 project authors. All rights reserved.; 2015 International Business Machines Corporation; 2012-2015 Dan Nicholson <dbn.lists@gmail.com>; and permission notice appear in associated; holder; 2013 Brian Eugene Wilson, Robert Martin Campbell.; 2000, 2001, 2002, 2003 Nara Institute of Science; 2004 Scott James Remnant <scott@netsplit.com>.; 2014 International Business Machines Corporation; AND PERMISSION NOTICE; holder.; 1999 TaBE Project.; 1991 by the Massachusetts Institute of Technology; 1999 Computer Systems and Communication Lab,; 2016 and later: Unicode, Inc. and others.; and permission notice appear with all copies; 1996 Chih-Hao Tsai @ Beckman Institute,; holders, disclaims all warranties with regard to this; 2006-2008, Google Inc.; 1999 Pai-Hsiang Hsiao.; 2013, LeRoy Benjamin Sharon");
		// Single line in NOTICE.txt
		EXPECTED_COPYRIGHTS.put("commons-codec", "2002-2023 The Apache Software Foundation");
		// Copryights in both NOTICE.md and LICENSE.md
		EXPECTED_COPYRIGHTS.put("jakarta.activation", "2018 Oracle and/or its affiliates. All rights reserved.; 1997, 2021 Oracle and/or its affiliates. All rights reserved.; All content is the property of the respective authors or their employers. For more information regarding authorship of content, please consult the listed source code repository logs.");
		// Copyright in source Jar
		EXPECTED_COPYRIGHTS.put("artemis-commons", "2023 The Apache Software Foundation");
		// Bundle vendor from MANIFEST.MF
		EXPECTED_COPYRIGHTS.put("microprofile-context-propagation-api", "Eclipse Foundation");
		// "bundle" artifact instead of "jar"
		EXPECTED_COPYRIGHTS.put("jakarta.ws.rs-api", "2011, 2021 Oracle and/or its affiliates. All rights reserved.; All content is the property of the respective authors or their employers. For more information regarding authorship of content, please consult the listed source code repository logs.");
	}
	
    public CopyrightDetectionTest(MavenRuntimeBuilder runtimeBuilder) throws Exception {
        super(runtimeBuilder);
    }

    @Test
    public void CopyrightExtraction() throws Exception {
        File projDir = resources.getBasedir("copyright-detection");

        verifier
                .forProject(projDir)
                .withCliOption("-Dcurrent.version=" + getCurrentVersion()) // inject cyclonedx-maven-plugin version
                .withCliOption("-X") // debug
                .withCliOption("-B")
                .execute("clean", "package")
                .assertErrorFreeLog();
        
        File bom = new File(projDir, "target/bom.json");

        for (Map.Entry<String, String> e : EXPECTED_COPYRIGHTS.entrySet()) {
        	JSONArray copyrights = JsonPath.read(bom, "$.components[?(@.name == '" + e.getKey() + "')].copyright");
        	assertEquals(1, copyrights.size(), "No copyright extracted for " + e.getKey());
			assertEquals(e.getValue(), copyrights.get(0), "Unexpected copyright extracted for " + e.getKey());
        }
    }
}
