package com.firebirdcss.tools.security.AWSRestAuth;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.firebirdcss.tools.security.AWSRestAuth.exceptions.MalformedUrlException;

/**
 * This class contains a general collection of utility methods.
 * 
 * @author Scott Griffis
 *
 */
public final class AwsAuthV2Util {
	
	/**
	 * This method uses the specified key to sign the given data.
	 * 
	 * @see https://www.javatips.net/api/netty-wamp-master/src/main/java/io/netty/protocol/wamp/cra/HmacSHA256.java
	 * 
	 * @param key - The secret key used to sign the data as {@link String}
	 * @param data - The data to sign as {@link String}
	 * @return Returns the generated signature as {@link String}
	 * 
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws UnsupportedEncodingException 
	 */
	public static  String signString(final String key, final String data) throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
		final String hashType = "HmacSHA1";
		if (key == null || data == null) throw new NullPointerException();
		final Mac hMacSHA256 = Mac.getInstance(hashType);
		byte[] hmacKeyBytes = key.getBytes(StandardCharsets.UTF_8);
		final SecretKeySpec secretKey = new SecretKeySpec(hmacKeyBytes, hashType);
		hMacSHA256.init(secretKey);
		byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
		byte[] res = hMacSHA256.doFinal(dataBytes);

		return Base64.encodeBase64String(res);
	}
	
	/**
	 * This method accepts a request and then generates the AWS StringToSign from the
	 * data contained in the request.
	 * 
	 * @see https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @param request - The request as {@link AWSRequest}
	 * @return Returns the generated StringToSign as {@link String}
	 * 
	 * @throws MalformedUrlException 
	 */
	public static String genStringToSign(AWSRequest request) {
		final StringBuilder stringToSign = new StringBuilder();
		String tempValue = "";
		
		/* Append RequestMethod */
		stringToSign.append(request.getRequestMethod()).append('\n');
		
		/* Append Content MD5 */
		if (!(tempValue = request.getSpecificHeaderValue("Content-MD5")).isEmpty()) {
			stringToSign.append(tempValue);
		}
		stringToSign.append('\n'); // Yes, this makes a place-holder if no ContentMD5
		
		/* Append Content Type */
		if (!(tempValue = request.getSpecificHeaderValue("Content-Type")).isEmpty()) {
			stringToSign.append(tempValue);
		}
		stringToSign.append('\n'); // Yep, This does the place-holder thing in no ContentType
		
		/* Append Date */
		if (!(tempValue = request.getSpecificHeaderValue("x-amz-date")).isEmpty()) { // This one is priority...
			stringToSign.append(tempValue).append('\n');
		} else if (!(tempValue = request.getSpecificHeaderValue("Date")).isEmpty()) { // If Priority not found...
			stringToSign.append(tempValue).append('\n');
		}
		
		/* Append Canonicalized Amazon Headers */
		if (!(tempValue = request.getCanonAmzHeaders()).isEmpty()) {
			stringToSign.append(tempValue).append('\n');
		}
		
		/* Append Canonicalized Resource */
		stringToSign.append(getCanonResource(request));
		
		
		return stringToSign.toString();
	}
	
	/**
	 * This method generates a properly formatted Authorization header for the given request.
	 * 
	 * @see https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#The%20Authentication%20Header
	 * 
	 * @param request - The request as {@link AWSRequest}
	 * @return Returns the generated Authorization header as {@link String}
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	public static String genAuthHeader(AWSRequest request) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		StringBuilder sb = new StringBuilder();
		sb
			.append("Authorization: AWS ")
			.append(request.getAccessKey())
			.append(':')
			.append(signString(request.getSecretKey(), genStringToSign(request)))
		;
		
		return sb.toString();
	}
	
	/**
	 * PRIVATE METHOD: This method is used to get the CanonicalizedResource from a request.
	 * 
	 * @see https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#Request%20CanonicalizedResource%20Element
	 * 
	 * @param req - The request as {@link AWSRequest}
	 * @return Returns the CanonResource as {@link String}
	 */
	private static String getCanonResource(AWSRequest req) {
		StringBuilder sb = new StringBuilder();
		/* ************ *
		 * BUCKET STUFF *
		 * ************ */
		if (!req.getBucket().isEmpty()) {
			sb.append('/').append(req.getBucket());
		} else {
			sb.append('/');
		}
		
		/* ********************** *
		 * Path/Request-URI STUFF *
		 * ********************** */
		if (req.getPath().isEmpty()) {
			if (!req.getBucket().isEmpty()) {
				sb.append('/');
			}
		} else {
			if (!req.getBucket().isEmpty() && req.getPath().startsWith(req.getBucket())) {
				if (req.getPath().charAt(req.getBucket().length() + 1) == '/') {
					sb.append(req.getPath().substring(req.getBucket().length() + 1));
				} else {
					sb.append(req.getPath().substring(req.getBucket().length()));
				}
			} else {
				sb.append('/').append(req.getPath());
			}
		}
		sb.append(req.getSubSourceString());
		
		return sb.toString();
	}
}