package com.firebirdcss.tools.security.AWSRestAuth;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * This is a POJO used to hold the important values needed when calculating
 * the signature for an AWS Version 2 Request.
 * 
 * @author Scott Griffis
 *
 */
public class AWSRequest {
	private final String endpoint;
	private final String path;
	private final String bucket;
	private final String accessKey;
	private final String secretKey;
	private final String requestMethod;
	
	private final Map<String, String> parameters = new HashMap<>();
	private final Map<String, String> headers = new HashMap<>();
	
	/**
	 * 
	 * @param endpoint
	 * @param path
	 * @param accessKey
	 * @param secretKey
	 * @param requestMethod
	 * @param requestParameters
	 */
	public AWSRequest(
			String endpoint,
			String path,
			String bucket,
			String accessKey, 
			String secretKey, 
			String requestMethod,
			HashMap<String, String> requestParameters,
			HashMap<String, String> requestHeaders
	) {
		this.endpoint = endpoint == null ? "" : endpoint;
		if (endpoint != null && !endpoint.isEmpty()) {
			this.headers.put("Host", endpoint);
		}
		this.path = path == null ? "" : path;
		this.bucket = bucket == null ? "" : bucket;
		this.accessKey = accessKey == null ? "" : accessKey;
		this.secretKey = secretKey == null ? "" : secretKey;
		this.requestMethod = requestMethod == null ? "" : requestMethod;
		if (requestParameters != null) {
			this.parameters.putAll(requestParameters);
		}
		if (requestHeaders != null) {
			this.headers.putAll(requestHeaders);
		}
	}
	
	/**
	 * 
	 * @return
	 */
	public String getPath() {
		
		return this.path;
	}
	
	public String getRequestMethod() {
		return this.requestMethod;
	}

	public String getBaseUrl() {
		return this.endpoint;
	}
	
	public String getBucket() {
		return this.bucket;
	}
	
	public String getAccessKey() {
		return this.accessKey;
	}

	public String getSecretKey() {
		return this.secretKey;
	}
	
	public String getQueryString() {
		StringBuilder sb = new StringBuilder();
		int c = 0;
		for (String key : this.getSortedParamKeys()) {
			if (++c > 1) sb.append('&');
			sb.append(key).append('=').append(this.parameters.get(key));
		}
		
		return sb.toString();
	}
	
	public String getCanonAmzHeaders() {
		ArrayList<String> headers = new ArrayList<>();
		StringBuilder sb = new StringBuilder();
		
		for (Entry<String, String> entry : this.headers.entrySet()) {
			if (entry.getKey().toLowerCase().startsWith("x-amz-") && !entry.getKey().equalsIgnoreCase("x-amz-date")) {
				headers.add(entry.getKey().toLowerCase() + ":" + entry.getValue());
			}
		}
		
		Collections.sort(headers);
		
		int c = 0;
		for (String header : headers) {
			if (++c > 1) sb.append('\n');
			sb.append(header);
		}
		
		return sb.toString();
	}
	
	public String getSpecificHeaderValue(String headerKey) {
		for (String key : this.headers.keySet()) {
			if (key.equalsIgnoreCase(headerKey)) {
				
				return this.headers.get(key);
			}
		}
		
		return "";
	}
	
	public String[] getQueryParameters() {
		ArrayList<String> results = new ArrayList<>();
		for (Entry<String, String> entry : this.parameters.entrySet()) {
			results.add(entry.getKey() + "=" + entry.getValue());
		}
		
		Collections.sort(results);
		
		return results.toArray(new String[] {});
	}
	
	public String getSubSourceString() {
		ArrayList<String> results = new ArrayList<>();
		for (Entry<String, String> entry : this.parameters.entrySet()) {
			if (entry.getValue() == null) {
				results.add(entry.getKey());
			}
		}
		
		Collections.sort(results);
		
		StringBuilder sb = new StringBuilder();
		int c = 0;
		for (String s : results) {
			if (++c == 1) { 
				sb.append('?');
			} else { 
				sb.append('&');
			}
			sb.append(s);
		}
		
		return sb.toString();
	}
	
	private String[] getSortedParamKeys() {
		ArrayList<String> results = new ArrayList<>();
		for (String key : this.parameters.keySet()) {
			results.add(key);
		}
		
		Collections.sort(results);
		
		return results.toArray(new String[] {});
	}
	
	/**
	 * 
	 * @return
	 * @throws UnsupportedEncodingException
	 */
	public String getParamsForUrl() throws UnsupportedEncodingException {
		StringBuilder sb = new StringBuilder();
		int c = 0;
		for (String key : this.getSortedParamKeys()) {
			if (++c > 1) sb.append('&');
			sb.append(key).append('=').append(URLEncoder.encode(this.parameters.get(key), "UTF-8"));
		}
		
		
		
		return sb.toString();
	}
}
