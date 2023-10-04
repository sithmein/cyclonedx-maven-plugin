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

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.manager.ArtifactHandlerManager;
import org.apache.maven.artifact.resolver.ArtifactResolutionRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.repository.RepositorySystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Singleton class that tries to extract copyright information from certain well-known files inside the artifact jars.
 * It look for "license" and "notice" files (in several spelling variants) and then matches lines or blocks that
 * look like copyright information. There is also a filter list which removes common patterns that are <b>not</b>
 * copyrights.
 */
public class CopyrightExtrator {
	private static CopyrightExtrator instance;
	private final Logger logger = LoggerFactory.getLogger(CopyrightExtrator.class);
	
	private final List<Pattern> copyrightFilterPatterns = new ArrayList<>();
	
    private static final Pattern COPYRIGHT_FILE_PATTERN = Pattern.compile("(?i)(?:.+/)?(?:[^/]+-)?(?:notice|license|licence|pom)(?:\\.(?:md|txt|xml))?$");

    private static final Pattern COPYRIGHT_LINE_PATTERN = Pattern.compile("(?i)Copyright\\s+(?:(?:©|\\(c\\)|holder>\\s*=)\\s+)?(.+?)[\\s\"]*$");
    
    private static final Pattern COPYRIGHT_LICENSE_COMBINATION_PATTERN = Pattern.compile("^(?i)(.+)\\.\\s.+license\\.$");
    
    private static final Pattern COPYRIGHT_BLOCK_PATTERN = Pattern.compile("^\\s*##\\s*Copyright\\s*$");
    
    private CopyrightExtrator() {
    	// Read filter patterns
    	try (BufferedReader in = new BufferedReader(new InputStreamReader(getClass().getResourceAsStream("/copyright-filters.txt")))) {
    		String line;
    		while ((line = in.readLine()) != null) {
    			if (!line.startsWith("#")) {
    				copyrightFilterPatterns.add(Pattern.compile("(?i)" + line));
    			}
    		}
    	} catch (IOException ex) {
    		logger.error("Could not read copyright filters, not filtering will be applied: " + ex.getMessage(), ex);
    	}
    }
    
    /**
     * Returns the singleton instance.
     * 
     * @return the singleton instance
     */
    public static CopyrightExtrator getInstance() {
    	if (instance == null) {
    		instance = new CopyrightExtrator();
    	}
    	return instance;
    }
    
    /**
     * Extract copyright information from the provided Maven project. The repository system and artifact handler
     * manager are used to resolve the corresponding artifact files.
     * 
     * @param project a Maven project
     * @param repositorySystem a repository system for artifact resolution
     * @param artifactHandlerManager an artifact handler manager for artifact resolution
     * @return a string with all extracted copyrights or an empty optional if no copyrights were found
     */
	public Optional<String> extractCopyright(MavenProject project, RepositorySystem repositorySystem,
			ArtifactHandlerManager artifactHandlerManager) {
		if ("pom".equals(project.getPackaging())) {
			return Optional.empty();
		}
    	Artifact artifact = project.getArtifact();
    	if ("bundle".equals(artifact.getType())) {
			artifact = new DefaultArtifact(artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(),
					artifact.getScope(), "jar", artifact.getClassifier(),
					artifactHandlerManager.getArtifactHandler("jar"));
    	}
    	
		Set<String> textFileCopyrights = new HashSet<>();
		Set<String> manifestCopyrights = new HashSet<>();

		// process main artifact
    	processArtifact(repositorySystem, artifact, textFileCopyrights, manifestCopyrights);
    	
    	// process source artifact as well
		artifact = new DefaultArtifact(artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(),
				artifact.getScope(), "java-source", artifact.getClassifier(),
				artifactHandlerManager.getArtifactHandler("java-source"));
		processArtifact(repositorySystem, artifact, textFileCopyrights, manifestCopyrights);		
    	
		// If we found something useful in text files, only use this information. The manifests don't contain
		// explicit copyright information but we can use it as such if there is nothing else.
		Set<String> finalCopyrights = !textFileCopyrights.isEmpty() ? textFileCopyrights : manifestCopyrights;
		return finalCopyrights.isEmpty() ? Optional.empty()
				: Optional.of(finalCopyrights.stream().collect(Collectors.joining("; ")));
    }

	private void processArtifact(RepositorySystem repositorySystem, Artifact artifact, Set<String> textFileCopyrights,
			Set<String> manifestCopyrights) {
		if (!artifact.isResolved()) {
    		ArtifactResolutionRequest request = new ArtifactResolutionRequest().setArtifact(artifact);
    		repositorySystem.resolve(request);
    	}
    	File artifactFile = artifact.getFile();
    	if ((artifactFile == null) || !artifactFile.exists()) {
    		logger.warn("Artifact {} has no valid file set, cannot extract copyright information.", artifact);
    	} else if (artifactFile.getName().endsWith(".jar")) {
    		try (ZipFile zipFile = new ZipFile(artifactFile)) {
    			Enumeration<? extends ZipEntry> entries = zipFile.entries();
    			while (entries.hasMoreElements()) {
    				ZipEntry zipEntry = entries.nextElement();
    				String fileName = zipEntry.getName().toLowerCase();
    				if (COPYRIGHT_FILE_PATTERN.matcher(fileName).matches()) {
    					scanTextFileForCopyright(zipFile, zipEntry, textFileCopyrights);
    				} else if (fileName.equals("meta-inf/manifest.mf")) {
    					scanManifestForCopyright(zipFile, zipEntry, manifestCopyrights);
    				}
    			}
    		} catch (IOException ex) {
    			logger.warn("Could not read Zip file: " + ex.getMessage(), ex);
    		}
    	}
	}
    
	private static void scanManifestForCopyright(ZipFile zipFile, ZipEntry entry, Set<String> copyrights)
			throws IOException {
		try (InputStream inputStream = zipFile.getInputStream(entry)) {
			Manifest manifest = new Manifest(inputStream);
			final Attributes mainAttributes = manifest.getMainAttributes();
			// Fetch Java standard JAR manifest attributes.
			Object implementationVendor = mainAttributes.get(Attributes.Name.IMPLEMENTATION_VENDOR);
			if (implementationVendor instanceof String) {
				copyrights.add((String) implementationVendor);
			}
			
			String bundleVendor = mainAttributes.getValue("Bundle-Vendor");
			if (bundleVendor != null) {
				copyrights.add(bundleVendor);
			}
		}
	}

	private void scanTextFileForCopyright(ZipFile zipFile, ZipEntry entry, Set<String> copyrights) throws IOException {
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(zipFile.getInputStream(entry)))) {
			String line;
			while ((line = reader.readLine()) != null) {
				Matcher lineMatcher = COPYRIGHT_LINE_PATTERN.matcher(line);
				if (lineMatcher.find() && !ignoreLine(lineMatcher.group(1))) {
					logger.info("Found match in {}/{}: {}", zipFile.getName(), entry.getName(), lineMatcher.group(1));
					copyrights.add(postProcessLine(lineMatcher.group(1).trim()));
				} else {
					Matcher blockMatcher = COPYRIGHT_BLOCK_PATTERN.matcher(line);
					if (blockMatcher.find()) {
						extractCopyrightBlock(reader, copyrights);
					}
				}
			}
		}
	}
	
	private void extractCopyrightBlock(BufferedReader reader, Set<String> copyrights) throws IOException {
		StringBuilder copyrightBlock = new StringBuilder();
		String line;
		while ((line = reader.readLine()) != null) {
			String trimmedLine = line.trim();
			if (trimmedLine.startsWith("## ")) {
				// the next block starts
				break;
			} else if (!trimmedLine.isEmpty()) {
				Matcher lineMatcher = COPYRIGHT_LINE_PATTERN.matcher(line);
				if (lineMatcher.find() && !ignoreLine(lineMatcher.group(1))) {
					copyrights.add(lineMatcher.group(1).trim());
				} else {
					copyrightBlock.append(trimmedLine).append(' ');
				}
			}
		}
		String trimmedBlock = copyrightBlock.toString().replaceFirst("^(?i)copyright\\s*", "").trim();
		if (!trimmedBlock.isEmpty()) {
			copyrights.add(postProcessLine(trimmedBlock));
		}
	}
	
	private static String postProcessLine(String line) {
		Matcher m = COPYRIGHT_LICENSE_COMBINATION_PATTERN.matcher(line);
		if (m.matches()) {
			return m.group(1);
		}
		return line;
	}
	
	private boolean ignoreLine(String line) {
		return copyrightFilterPatterns.stream().anyMatch(p -> p.matcher(line).find());
	}
}
