/*-
 * #%L
 * athena-udfs
 * %%
 * Copyright (C) 2019 Amazon Web Services
 * %%
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
 * #L%
 */
package com.amazonaws.athena.connectors.udfs;

import com.amazonaws.athena.connector.lambda.handlers.UserDefinedFunctionHandler;
import com.amazonaws.athena.connector.lambda.security.CachableSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClient;
import com.google.common.annotations.VisibleForTesting;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.TimeZone;

public class AthenaUDFHandler
        extends UserDefinedFunctionHandler
{
    private static final String SOURCE_TYPE = "athena_common_udfs";

    private final CachableSecretsManager cachableSecretsManager;

    public AthenaUDFHandler()
    {
        this(new CachableSecretsManager(AWSSecretsManagerClient.builder().build()));
    }

    @VisibleForTesting
    AthenaUDFHandler(CachableSecretsManager cachableSecretsManager)
    {
        super(SOURCE_TYPE);
        this.cachableSecretsManager = cachableSecretsManager;
    }
    
    public String healthcheck(String input)
    {
        return input;
    }
    
    private byte[] calcHmacSha256(byte[] secretKey, byte[] message)
    {
        byte[] hmacSha256 = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
            mac.init(secretKeySpec);
            hmacSha256 = mac.doFinal(message);
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to calculate hmac-sha256", e);
        }
        return hmacSha256;
    }
    
    /**
     * Converts employee_id to email with Talenta Data API
     * 
     *
     * @param input the employee_id
     * @return the returned email address
     */
    public String convert(Long employeeID) throws Exception
    {
        String hmacUsername = "TALENTA_DATA_API_USERNAME";
        String hmacSecret = "TALENTA_DATA_API_SECRET";
        String baseURL = "https://talenta-data-api.sleekr.id/v1/employee/";

        //get request path
        String urlString = baseURL + employeeID;
        URL requestURL = new URL(urlString);
        String requestPath = requestURL.getPath();
        String requestLine = "GET" + ' ' + requestPath + " HTTP/1.1";

        //date string code
        final Date currentTime = new Date();
        final SimpleDateFormat sdf = new SimpleDateFormat("E, dd MMM yyyy HH:mm:ss z");
        sdf.setTimeZone(TimeZone.getTimeZone("GMT"));
        String dateString = sdf.format(currentTime);

        //calculate HMAC 256
        String temp = "date: " + dateString + "\n" + requestLine;
        byte[] digest = calcHmacSha256(hmacSecret.getBytes(), temp.getBytes());
        String signature = Base64.getEncoder().encodeToString(digest);

        String hmacHeader = String.format("hmac username=\"%s\", algorithm=\"hmac-sha256\", headers=\"date request-line\", signature=\"%s\"", hmacUsername, signature);

        CloseableHttpClient httpclient = HttpClients.createDefault();

        //Creating a HttpGet object
        HttpGet httpget = new HttpGet(urlString);
        httpget.setHeader("Authorization", hmacHeader);
        httpget.setHeader("Date", dateString);

        //Executing the Get request
        HttpResponse httpresponse = httpclient.execute(httpget);

        //parsing response body to JSON
        String responseBodyString = EntityUtils.toString(httpresponse.getEntity());
        JSONParser parser = new JSONParser();
        JSONObject responseJSON = (JSONObject) parser.parse(responseBodyString);

        JSONObject data = (JSONObject) responseJSON.get("data");
        JSONObject personal = (JSONObject) data.get("personal");

        //Get Email
        String email = personal.get("email").toString();

        return email;
    }
}
