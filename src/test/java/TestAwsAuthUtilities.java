import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import org.junit.Test;

import com.firebirdcss.tools.security.AWSRestAuth.AWSRequest;
import com.firebirdcss.tools.security.AWSRestAuth.AwsAuthV2Util;

import io.netty.handler.codec.http.HttpMethod;
import static org.junit.Assert.*;


/**
 * JUNIT TESTS: This class makes up the JUNIT Tests for the utility methods found in the 
 * {@link AwsAuthV2Util} class.
 * 
 * @author Scott Griffis
 *
 */
public class TestAwsAuthUtilities {
	private static final String ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
	private static final String SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	
	/**
	 * UNIT TEST: This test is of the "Object GET" request as specified at the
	 * following URL: https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testObjectGet() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		HashMap<String, String> reqParams = new HashMap<>();
		HashMap<String, String> reqHeads = new HashMap<>();
		reqHeads.put("Date", "Tue, 27 Mar 2007 19:36:42 +0000");
		
		AWSRequest req = new AWSRequest("johnsmith.s3.amazonaws.com", "photos/puppy.jpg", "johnsmith", ACCESS_KEY, SECRET_KEY, HttpMethod.GET.name(), reqParams, reqHeads);
		
		String stringToSign = "";
		assertEquals("GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg", (stringToSign = AwsAuthV2Util.genStringToSign(req)));
		assertEquals("bWq2s1WEIj+Ydj0vQ697zp+IXMU=", AwsAuthV2Util.signString(SECRET_KEY, stringToSign));
		assertEquals("Authorization: AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=", AwsAuthV2Util.genAuthHeader(req));
	}
	
	/**
	 * UNIT TEST: This test is of the "Object PUT" request as specified at the
	 * following URL: https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testObjectPut() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		HashMap<String, String> reqParams = new HashMap<>();
		HashMap<String, String> reqHeads = new HashMap<>();
		reqHeads.put("Date", "Tue, 27 Mar 2007 21:15:45 +0000");
		reqHeads.put("Content-Length", "94328");
		reqHeads.put("Content-Type", "image/jpeg");
		
		AWSRequest req = new AWSRequest("johnsmith.s3.amazonaws.com", "photos/puppy.jpg", "johnsmith", ACCESS_KEY, SECRET_KEY, HttpMethod.PUT.name(), reqParams, reqHeads);
		
		String stringToSign = "";
		assertEquals("PUT\n\nimage/jpeg\nTue, 27 Mar 2007 21:15:45 +0000\n/johnsmith/photos/puppy.jpg", (stringToSign = AwsAuthV2Util.genStringToSign(req)));
		assertEquals("MyyxeRY7whkBe+bq8fHCL/2kKUg=", AwsAuthV2Util.signString(SECRET_KEY, stringToSign));
		assertEquals("Authorization: AWS AKIAIOSFODNN7EXAMPLE:MyyxeRY7whkBe+bq8fHCL/2kKUg=", AwsAuthV2Util.genAuthHeader(req));
	}
	
	/**
	 * UNIT TEST: This test is of the "List" request as specified at the
	 * following URL: https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testList() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		HashMap<String, String> reqParams = new HashMap<>();
		reqParams.put("prefix", "photos");
		reqParams.put("marker", "puppy");
		reqParams.put("max-keys", "50");
		HashMap<String, String> reqHeads = new HashMap<>();
		reqHeads.put("Date", "Tue, 27 Mar 2007 19:42:41 +0000");
		reqHeads.put("User-Agent", "Mozilla/5.0");
		
		AWSRequest req = new AWSRequest("johnsmith.s3.amazonaws.com", null, "johnsmith", ACCESS_KEY, SECRET_KEY, HttpMethod.GET.name(), reqParams, reqHeads);
		
		String stringToSign = "";
		assertEquals("GET\n\n\nTue, 27 Mar 2007 19:42:41 +0000\n/johnsmith/", (stringToSign = AwsAuthV2Util.genStringToSign(req)));
		assertEquals("htDYFYduRNen8P9ZfE/s9SuKy0U=", AwsAuthV2Util.signString(SECRET_KEY, stringToSign));
		assertEquals("Authorization: AWS AKIAIOSFODNN7EXAMPLE:htDYFYduRNen8P9ZfE/s9SuKy0U=", AwsAuthV2Util.genAuthHeader(req));
	}
	
	/**
	 * UNIT TEST: This test is of the "Fetch" request as specified at the
	 * following URL: https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testFetch() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		HashMap<String, String> reqParams = new HashMap<>();
		reqParams.put("acl", null);
		HashMap<String, String> reqHeads = new HashMap<>();
		reqHeads.put("Date", "Tue, 27 Mar 2007 19:44:46 +0000");
		
		AWSRequest req = new AWSRequest("johnsmith.s3.amazonaws.com", null, "johnsmith", ACCESS_KEY, SECRET_KEY, HttpMethod.GET.name(), reqParams, reqHeads);
		
		String stringToSign = "";
		assertEquals("GET\n\n\nTue, 27 Mar 2007 19:44:46 +0000\n/johnsmith/?acl", (stringToSign = AwsAuthV2Util.genStringToSign(req)));
		assertEquals("c2WLPFtWHVgbEmeEG93a4cG37dM=", AwsAuthV2Util.signString(SECRET_KEY, stringToSign));
		assertEquals("Authorization: AWS AKIAIOSFODNN7EXAMPLE:c2WLPFtWHVgbEmeEG93a4cG37dM=", AwsAuthV2Util.genAuthHeader(req));
	}
	
	/**
	 * UNIT TEST: This test is of the "Delete" request as specified at the
	 * following URL: https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testDelete() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		HashMap<String, String> reqParams = new HashMap<>();
		HashMap<String, String> reqHeads = new HashMap<>();
		reqHeads.put("User-Agent:", "dotnet");
		reqHeads.put("Date", "Tue, 27 Mar 2007 21:20:27 +0000");
		reqHeads.put("x-amz-date", "Tue, 27 Mar 2007 21:20:26 +0000");
		
		AWSRequest req = new AWSRequest("s3.amazonaws.com", "johnsmith/photos/puppy.jpg", "johnsmith", ACCESS_KEY, SECRET_KEY, HttpMethod.DELETE.name(), reqParams, reqHeads);
		
		String stringToSign = "";
		assertEquals("DELETE\n\n\nTue, 27 Mar 2007 21:20:26 +0000\n/johnsmith/photos/puppy.jpg", (stringToSign = AwsAuthV2Util.genStringToSign(req)));
		assertEquals("lx3byBScXR6KzyMaifNkardMwNk=", AwsAuthV2Util.signString(SECRET_KEY, stringToSign));
		assertEquals("Authorization: AWS AKIAIOSFODNN7EXAMPLE:lx3byBScXR6KzyMaifNkardMwNk=", AwsAuthV2Util.genAuthHeader(req));
	}
	
	/**
	 * UNIT TEST: This test is of the "Upload" request as specified at the
	 * following URL: https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testUpload() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		HashMap<String, String> reqParams = new HashMap<>();
		HashMap<String, String> reqHeads = new HashMap<>();
		reqHeads.put("User-Agent", "curl/7.15.5");
		reqHeads.put("Date", "Tue, 27 Mar 2007 21:06:08 +0000");
		reqHeads.put("x-amz-acl", "public-read");
		reqHeads.put("content-type", "application/x-download");
		reqHeads.put("Content-MD5", "4gJE4saaMU4BqNR0kLY+lw==");
		reqHeads.put("X-Amz-Meta-ReviewedBy", "joe@johnsmith.net,jane@johnsmith.net");
		reqHeads.put("X-Amz-Meta-FileChecksum", "0x02661779");
		reqHeads.put("X-Amz-Meta-ChecksumAlgorithm", "crc32");
		reqHeads.put("Content-Disposition", "attachment; filename=database.dat");
		reqHeads.put("Content-Encoding", "gzip");
		reqHeads.put("Content-Length", "5913339");
		
		AWSRequest req = new AWSRequest("static.johnsmith.net:8080", "db-backup.dat.gz", "static.johnsmith.net", ACCESS_KEY, SECRET_KEY, HttpMethod.PUT.name(), reqParams, reqHeads);
		
		String stringToSign = "";
		assertEquals("PUT\n4gJE4saaMU4BqNR0kLY+lw==\napplication/x-download\nTue, 27 Mar 2007 21:06:08 +0000\nx-amz-acl:public-read\nx-amz-meta-checksumalgorithm:crc32\nx-amz-meta-filechecksum:0x02661779\nx-amz-meta-reviewedby:joe@johnsmith.net,jane@johnsmith.net\n/static.johnsmith.net/db-backup.dat.gz", (stringToSign = AwsAuthV2Util.genStringToSign(req)));
		assertEquals("ilyl83RwaSoYIEdixDQcA4OnAnc=", AwsAuthV2Util.signString(SECRET_KEY, stringToSign));
		assertEquals("Authorization: AWS AKIAIOSFODNN7EXAMPLE:ilyl83RwaSoYIEdixDQcA4OnAnc=", AwsAuthV2Util.genAuthHeader(req));
	}
	
	/**
	 * UNIT TEST: This test is of the "List All My Buckets" request as specified at the
	 * following URL: https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testListAllMyBuckets() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		HashMap<String, String> reqParams = new HashMap<>();
		HashMap<String, String> reqHeads = new HashMap<>();
		reqHeads.put("Date", "Wed, 28 Mar 2007 01:29:59 +0000");
		
		AWSRequest req = new AWSRequest("s3.amazonaws.com", null, null, ACCESS_KEY, SECRET_KEY, HttpMethod.GET.name(), reqParams, reqHeads);
		
		String stringToSign = "";
		assertEquals("GET\n\n\nWed, 28 Mar 2007 01:29:59 +0000\n/", (stringToSign = AwsAuthV2Util.genStringToSign(req)));
		assertEquals("qGdzdERIC03wnaRNKh6OqZehG9s=", AwsAuthV2Util.signString(SECRET_KEY, stringToSign));
		assertEquals("Authorization: AWS AKIAIOSFODNN7EXAMPLE:qGdzdERIC03wnaRNKh6OqZehG9s=", AwsAuthV2Util.genAuthHeader(req));
	}
	
	/**
	 * UNIT TEST: This test is of the "Unicode Keys" request as specified at the
	 * following URL: https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html
	 * 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws UnsupportedEncodingException
	 */
	@Test
	public void testUnicodeKeys() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException {
		HashMap<String, String> reqParams = new HashMap<>();
		HashMap<String, String> reqHeads = new HashMap<>();
		reqHeads.put("Date", "Wed, 28 Mar 2007 01:49:49 +0000");
		
		AWSRequest req = new AWSRequest("s3.amazonaws.com", "fran%C3%A7ais/pr%c3%a9f%c3%a8re", "dictionary", ACCESS_KEY, SECRET_KEY, HttpMethod.GET.name(), reqParams, reqHeads);
		
		String stringToSign = "";
		assertEquals("GET\n\n\nWed, 28 Mar 2007 01:49:49 +0000\n/dictionary/fran%C3%A7ais/pr%c3%a9f%c3%a8re", (stringToSign = AwsAuthV2Util.genStringToSign(req)));
		assertEquals("DNEZGsoieTZ92F3bUfSPQcbGmlM=", AwsAuthV2Util.signString(SECRET_KEY, stringToSign));
		assertEquals("Authorization: AWS AKIAIOSFODNN7EXAMPLE:DNEZGsoieTZ92F3bUfSPQcbGmlM=", AwsAuthV2Util.genAuthHeader(req));
	}
}
