/*
 * Copyright 2010-2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
import {sigV4ClientFactory} from './sigv4-client';
import {simpleHttpClientFactory} from './simple-http-client';
import {utils} from './utils';

export const apiGatewayClientFactory = {
  newClient: function (simpleHttpClientConfig: any, sigV4ClientConfig: any) {

      // spin up 2 httpClients, one for simple requests, one for SigV4
      var sigV4Client = sigV4ClientFactory.newClient(sigV4ClientConfig);
      var simpleHttpClient = simpleHttpClientFactory.newClient(simpleHttpClientConfig);

      var apiGatewayClient = {
        makeRequest: function (request: any, authType: any, additionalParams: any, apiKey: any) {

            // attach the apiKey to the headers request if one was provided
            if (apiKey !== undefined && apiKey !== '' && apiKey !== null) {
                request.headers['x-api-key'] = apiKey;
            }

            if (request.body === undefined || request.body === '' || request.body === null || Object.keys(request.body).length === 0) {
                request.body = undefined;
            }

            // if the user specified any additional headers or query params that may not have been modeled
            // merge them into the appropriate request properties
            request.headers = utils.mergeInto(request.headers, additionalParams.headers);
            request.queryParams = utils.mergeInto(request.queryParams, additionalParams.queryParams);

            // if an auth type was specified inject the appropriate auth client
            // call the selected http client to make the request, returning a promise once the request is sent
            if (authType === 'AWS_IAM') {
                return sigV4Client.makeRequest(request);
            } else {
              // default the request to use the simple http client
              return simpleHttpClient.makeRequest(request);
            }
        }
      };

      return apiGatewayClient;
  }
};
