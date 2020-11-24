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

import com.amazonaws.athena.connector.lambda.security.CachableSecretsManager;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;
import java.util.zip.DataFormatException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AthenaUDFHandlerTest
{
    private static final String DUMMY_SECRET_NAME = "dummy_secret";

    private AthenaUDFHandler athenaUDFHandler;

    private static final String PLAINTEXT_DATA_KEY = "AQIDBAUGBwgJAAECAwQFBg==";

    private Base64.Decoder decoder = Base64.getDecoder();
    private Base64.Encoder encoder = Base64.getEncoder();

    @Before
    public void setup()
    {
        CachableSecretsManager cachableSecretsManager = mock(CachableSecretsManager.class);
        when(cachableSecretsManager.getSecret(DUMMY_SECRET_NAME)).thenReturn(PLAINTEXT_DATA_KEY);
        this.athenaUDFHandler = new AthenaUDFHandler(cachableSecretsManager);
    }
}
